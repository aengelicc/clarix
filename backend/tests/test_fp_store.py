"""Tests for the false-positive tracking store + analyzer integration.

Covers:
- fp_store: hash_description, add_mark, is_marked, list_marks,
  remove_mark, clear, validation (file_path required, exactly one of
  rule_id/description_hash), idempotency
- Analyzer wiring: per-file and bundle modes drop issues that match a
  marked FP (both static rule_id matches and LLM description_hash
  matches); unmarked issues pass through
- API: GET / POST / DELETE round-trip via FastAPI TestClient
"""
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.services import fp_store
from app.services.analyzer import CodeAnalyzer

# ---------------------------------------------------------------------------
# fp_store unit tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_marks():
    fp_store.clear()
    yield
    fp_store.clear()


def test_hash_description_is_stable_and_prefixed():
    h1 = fp_store.hash_description("User input not sanitized")
    h2 = fp_store.hash_description("User input not sanitized")
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_hash_description_differs_for_different_input():
    a = fp_store.hash_description("A")
    b = fp_store.hash_description("B")
    assert a != b


def test_add_mark_rule_id_creates_record():
    mark = fp_store.add_mark(
        file_path="src/auth.py",
        rule_id="sec-secret-001",
        reason="Test fixture",
    )
    assert mark["id"]
    assert mark["file_path"] == "src/auth.py"
    assert mark["rule_id"] == "sec-secret-001"
    assert mark["description_hash"] is None
    assert mark["reason"] == "Test fixture"
    assert mark["marked_at"]


def test_add_mark_description_hash_creates_record():
    h = fp_store.hash_description("Some LLM finding")
    mark = fp_store.add_mark(
        file_path="src/foo.py",
        description_hash=h,
    )
    assert mark["rule_id"] is None
    assert mark["description_hash"] == h


def test_add_mark_requires_file_path():
    with pytest.raises(ValueError, match="file_path is required"):
        fp_store.add_mark(file_path="", rule_id="x")


def test_add_mark_requires_exactly_one_key():
    with pytest.raises(ValueError, match="Exactly one of"):
        fp_store.add_mark(file_path="a.py")  # neither
    with pytest.raises(ValueError, match="Exactly one of"):
        fp_store.add_mark(
            file_path="a.py", rule_id="r1", description_hash="sha256:abc",
        )


def test_add_mark_is_idempotent():
    m1 = fp_store.add_mark(file_path="a.py", rule_id="r1", reason="first")
    m2 = fp_store.add_mark(file_path="a.py", rule_id="r1", reason="second")
    assert m1["id"] == m2["id"]
    # Reason from the first add is preserved (idempotent update)
    assert m2["reason"] == "first"
    assert fp_store.size() == 1


def test_is_marked_rule_id_match():
    fp_store.add_mark(file_path="a.py", rule_id="r1")
    assert fp_store.is_marked("a.py", rule_id="r1") is True
    assert fp_store.is_marked("a.py", rule_id="r2") is False
    assert fp_store.is_marked("b.py", rule_id="r1") is False


def test_is_marked_description_hash_match():
    h = fp_store.hash_description("some text")
    fp_store.add_mark(file_path="a.py", description_hash=h)
    assert fp_store.is_marked("a.py", description_hash=h) is True
    assert fp_store.is_marked("a.py", description_hash="sha256:other") is False


def test_is_marked_requires_filepath():
    assert fp_store.is_marked("", rule_id="r1") is False
    assert fp_store.is_marked(None, rule_id="r1") is False  # type: ignore[arg-type]


def test_remove_mark_returns_true_when_removed():
    m = fp_store.add_mark(file_path="a.py", rule_id="r1")
    assert fp_store.remove_mark(m["id"]) is True
    assert fp_store.size() == 0


def test_remove_mark_returns_false_when_missing():
    assert fp_store.remove_mark("nonexistent-id") is False


def test_list_marks_returns_copy():
    fp_store.add_mark(file_path="a.py", rule_id="r1")
    marks = fp_store.list_marks()
    marks.clear()  # mutate the returned list
    assert fp_store.size() == 1  # store is unaffected


# ---------------------------------------------------------------------------
# Analyzer integration: FP marks drop issues from the report
# ---------------------------------------------------------------------------


class _StubLLM:
    """Returns canned LLM issues with descriptions the test can mark."""
    def __init__(self, llm_issues_per_file: dict[str, list[dict]] | None = None) -> None:
        self.provider = "stub"
        self.model = "stub-model"
        self.llm_issues_per_file = llm_issues_per_file or {}

    def analyze_file(self, file_path: str, language: str, content: str, **kwargs) -> dict:
        return {
            "issues": self.llm_issues_per_file.get(file_path, []),
            "summary": "stub",
        }

    def analyze_bundle(self, files: list, **kwargs) -> dict:
        flat = []
        for f in files:
            for issue in self.llm_issues_per_file.get(f["path"], []):
                flat.append({**issue, "file": f["path"]})
        return {"issues": flat, "project_level_issues": [], "overall_assessment": "stub", "overall_risk_score": 0}

    def synthesize_project(self, file_summaries, all_issues, **kwargs) -> dict:
        return {"project_level_issues": [], "overall_assessment": "stub", "overall_risk_score": 0}


def _make_static_file(tmp: Path, rel_path: str, body: str) -> Path:
    f = tmp / rel_path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body, encoding="utf-8")
    return f


def test_analyzer_drops_static_issue_marked_as_fp_per_file():
    """Per-file mode: an FP mark on (file, rule_id) drops the matching static issue."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # File with a pickle.loads pattern (OWASP A08 → rule_id 'owasp-...')
        vuln = _make_static_file(tmp_path, "app.py", "import pickle\ndata = pickle.loads(request.body)\n")

        # First scan without any marks — get a baseline rule_id from the report.
        baseline = CodeAnalyzer(llm_client=_StubLLM()).analyze_repo(
            repo_path=str(tmp_path),
            files=[(Path("app.py"), "Python", vuln.stat().st_size)],
            repo_name="sample",
            source_type="local",
            mode="static",
        )
        baseline_issues = baseline.file_analyses[0].issues
        assert baseline_issues, "Expected at least one static issue in baseline"
        # Pick the first issue to mark
        target = baseline_issues[0]
        assert target.rule_id, "Test relies on static issues having a rule_id"

        fp_store.add_mark(
            file_path="app.py",
            rule_id=target.rule_id,
            reason="Reviewed; not actually a problem",
        )

        # Second scan — the marked issue should be gone.
        after = CodeAnalyzer(llm_client=_StubLLM()).analyze_repo(
            repo_path=str(tmp_path),
            files=[(Path("app.py"), "Python", vuln.stat().st_size)],
            repo_name="sample",
            source_type="local",
            mode="static",
        )
        after_issues = after.file_analyses[0].issues
        remaining_ids = {(i.file, i.rule_id) for i in after_issues}
        assert (target.file, target.rule_id) not in remaining_ids


def test_analyzer_drops_llm_issue_marked_as_fp_per_file():
    """Per-file mode: an FP mark on (file, description_hash) drops the matching LLM issue."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        f = _make_static_file(tmp_path, "app.py", "x = 1\n")
        llm_issue = {
            "category": "security",
            "severity": "high",
            "line": 1,
            "description": "Suspicious use of variable 'x' — possible secret leak",
            "recommendation": "Use a secrets manager",
        }
        # Mark the LLM issue as FP before scanning
        fp_store.add_mark(
            file_path="app.py",
            description_hash=fp_store.hash_description(llm_issue["description"]),
        )

        analyzer = CodeAnalyzer(llm_client=_StubLLM(llm_issues_per_file={"app.py": [llm_issue]}))
        report = analyzer.analyze_repo(
            repo_path=str(tmp_path),
            files=[(Path("app.py"), "Python", f.stat().st_size)],
            repo_name="sample",
            source_type="local",
            mode="per_file",
        )
        assert report.file_analyses[0].issues == []


def test_analyzer_drops_marked_issue_in_bundle_mode():
    """Bundle mode: same filter applies via _analyze_bundle path."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        f = _make_static_file(tmp_path, "app.py", "x = 1\n")
        llm_issue = {
            "category": "security",
            "severity": "high",
            "line": 1,
            "description": "Bundle mode FP test",
            "recommendation": "fix",
        }
        fp_store.add_mark(
            file_path="app.py",
            description_hash=fp_store.hash_description(llm_issue["description"]),
        )

        analyzer = CodeAnalyzer(llm_client=_StubLLM(llm_issues_per_file={"app.py": [llm_issue]}))
        report = analyzer.analyze_repo(
            repo_path=str(tmp_path),
            files=[(Path("app.py"), "Python", f.stat().st_size)],
            repo_name="sample",
            source_type="local",
            mode="bundle",
        )
        assert report.file_analyses[0].issues == []


def test_analyzer_unmarked_issues_pass_through():
    """Sanity: no marks → all issues survive."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        f = _make_static_file(tmp_path, "app.py", "import pickle\ndata = pickle.loads(request.body)\n")
        analyzer = CodeAnalyzer(llm_client=_StubLLM())
        report = analyzer.analyze_repo(
            repo_path=str(tmp_path),
            files=[(Path("app.py"), "Python", f.stat().st_size)],
            repo_name="sample",
            source_type="local",
            mode="static",
        )
        assert any(len(fa.issues) > 0 for fa in report.file_analyses)


# ---------------------------------------------------------------------------
# API: FastAPI TestClient round-trip
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)


def test_api_list_empty(client):
    r = client.get("/api/fp-marks")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 0
    assert body["marks"] == []


def test_api_post_and_get_round_trip(client):
    r = client.post("/api/fp-marks", json={
        "file_path": "src/foo.py",
        "rule_id": "sec-secret-001",
        "reason": "Test fixture",
    })
    assert r.status_code == 201
    created = r.json()
    assert created["file_path"] == "src/foo.py"
    assert created["rule_id"] == "sec-secret-001"
    mark_id = created["id"]

    r2 = client.get("/api/fp-marks")
    body = r2.json()
    assert body["count"] == 1
    assert body["marks"][0]["id"] == mark_id


def test_api_post_rejects_both_keys(client):
    r = client.post("/api/fp-marks", json={
        "file_path": "a.py",
        "rule_id": "r1",
        "description_hash": "sha256:abc",
    })
    assert r.status_code == 400
    assert "Exactly one of" in r.json()["detail"]


def test_api_post_rejects_missing_keys(client):
    r = client.post("/api/fp-marks", json={"file_path": "a.py"})
    assert r.status_code == 400


def test_api_post_is_idempotent(client):
    body = {"file_path": "a.py", "rule_id": "r1"}
    r1 = client.post("/api/fp-marks", json=body)
    r2 = client.post("/api/fp-marks", json=body)
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["id"] == r2.json()["id"]


def test_api_delete_existing(client):
    r = client.post("/api/fp-marks", json={"file_path": "a.py", "rule_id": "r1"})
    mark_id = r.json()["id"]
    d = client.delete(f"/api/fp-marks/{mark_id}")
    assert d.status_code == 204
    listing = client.get("/api/fp-marks").json()
    assert listing["count"] == 0


def test_api_delete_missing_returns_404(client):
    d = client.delete("/api/fp-marks/nonexistent-id")
    assert d.status_code == 404
