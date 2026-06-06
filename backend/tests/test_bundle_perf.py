"""Bundle mode perf test: makes sure the bundle path stays fast and uses exactly one LLM call.

Marked `@pytest.mark.slow` so `pytest -m "not slow"` skips it on quick runs.
Run all tests including slow: `pytest` (or `pytest -m slow` to run only this file).
"""
import tempfile
import time
from pathlib import Path

import pytest

from app.services.analyzer import CodeAnalyzer

# ---------------------------------------------------------------------------
# Stub LLM that doesn't touch the network and records every call site.
# ---------------------------------------------------------------------------


class _StubLLM:
    """Implements the three methods CodeAnalyzer actually calls.

    Real `LLMClient` instances are constructed with an api_key and validated
    in `_init_client`; we don't go through `__init__` at all here, so the
    stub is a clean drop-in for the analyzer without ever touching the SDK.
    """

    def __init__(self) -> None:
        self.provider = "stub"
        self.model = "stub-model"
        self.analyze_file_calls = 0
        self.analyze_bundle_calls = 0
        self.synthesize_project_calls = 0

    @property
    def call_count(self) -> int:
        return (
            self.analyze_file_calls
            + self.analyze_bundle_calls
            + self.synthesize_project_calls
        )

    def analyze_file(self, file_path: str, language: str, content: str) -> dict:
        self.analyze_file_calls += 1
        return {"issues": [], "summary": "stub"}

    def analyze_bundle(self, files: list) -> dict:
        self.analyze_bundle_calls += 1
        return {
            "issues": [],
            "project_level_issues": [],
            "overall_assessment": "stub assessment",
            "overall_risk_score": 10,
        }

    def synthesize_project(self, file_summaries: list, all_issues: list) -> dict:
        self.synthesize_project_calls += 1
        return {
            "project_level_issues": [],
            "overall_assessment": "stub",
            "overall_risk_score": 10,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_synthetic_repo(root: Path, n_files: int, line_pad: int = 40) -> list:
    """Create `n_files` small synthetic Python files in `root` and return
    the `(rel_path, language, size_bytes)` tuples the analyzer expects.

    Note: `rel_path` must be a relative `Path` (not an absolute one). If
    you pass an absolute path, the analyzer's `repo_path_obj / rel_path`
    is harmless (right side wins for absolute `Path`s), but
    `FileAnalysis.file_path` ends up as the absolute path string — so
    downstream assertions like `fa.file_path == "huge.py"` will silently
    fail. Keep this relative.
    """
    files = []
    for i in range(n_files):
        f = root / f"module_{i:03d}.py"
        body = (
            f"import os\nimport sys\n\n"
            f"def function_{i}(arg):\n"
            f"    # module {i}\n"
            f"    result = arg * 2\n"
        )
        body += "    # padding line to inflate token count\n" * line_pad
        f.write_text(body, encoding="utf-8")
        # Use a relative Path so FileAnalysis.file_path matches the basename.
        rel = Path(f"module_{i:03d}.py")
        files.append((rel, "Python", f.stat().st_size))
    return files


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_bundle_mode_completes_quickly():
    """Bundle mode should finish 30 files in well under 2 seconds with a stub LLM.

    Threshold is generous on purpose — the goal is to catch a quadratic-loop
    regression or a "second LLM call sneaking in", not to time the provider.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        files = _make_synthetic_repo(tmp_path, n_files=30)

        stub = _StubLLM()
        analyzer = CodeAnalyzer(llm_client=stub)

        t0 = time.perf_counter()
        report = analyzer.analyze_repo(
            repo_path=str(tmp_path),
            files=files,
            repo_name="synthetic",
            source_type="local",
            mode="bundle",
        )
        elapsed = time.perf_counter() - t0

        assert elapsed < 2.0, f"Bundle mode took {elapsed:.2f}s for 30 files; expected < 2s"
        assert report.metadata["analysis_mode"] == "bundle"
        # The whole point of bundle mode: one LLM call, not N+1.
        assert stub.analyze_bundle_calls == 1, f"Expected 1 bundle call, got {stub.analyze_bundle_calls}"
        assert stub.analyze_file_calls == 0, "analyze_file must not be called in bundle mode"
        assert stub.synthesize_project_calls == 0, "synthesize_project must not be called in bundle mode"
        # All 30 files should have been analyzed.
        assert report.metadata["total_files_analyzed"] == 30
        assert report.metadata["total_files_skipped"] == 0


@pytest.mark.slow
def test_bundle_mode_oversized_file_gets_skip_reason():
    """A file above `max_file_tokens` gets a skip_reason; the analyzer still produces a FileAnalysis for it.

    The huge file's static issues still count toward the report — that's the
    whole point of running static first, then deciding what to send to the LLM.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # 70k chars / 4 ≈ 17.5k tokens (well above the 8k per-file limit).
        # read_file_content truncates at 50k chars, which is still ~12.5k
        # estimated tokens — still over the 8k cap.
        huge = tmp_path / "huge.py"
        huge.write_text("x = 1\n" * 10_000, encoding="utf-8")
        # Pass RELATIVE Paths as the first element of each file tuple, so
        # FileAnalysis.file_path ends up as the basename (not the absolute
        # path) and the assertions below match.
        files: list = [(Path("huge.py"), "Python", huge.stat().st_size)]
        for i in range(3):
            f = tmp_path / f"small_{i}.py"
            f.write_text("y = 1\n", encoding="utf-8")
            files.append((Path(f"small_{i}.py"), "Python", f.stat().st_size))

        stub = _StubLLM()
        analyzer = CodeAnalyzer(llm_client=stub)
        report = analyzer.analyze_repo(
            repo_path=str(tmp_path),
            files=files,
            repo_name="synthetic",
            source_type="local",
            mode="bundle",
        )

        huge_fa = next(fa for fa in report.file_analyses if fa.file_path == "huge.py")
        assert huge_fa.skip_reason is not None
        assert "too large" in huge_fa.skip_reason.lower()
        # Exactly one bundle call (the 3 small files fit in the 150k budget).
        assert stub.analyze_bundle_calls == 1
        # The 3 small files were analyzed and sent to the LLM.
        small_fas = [fa for fa in report.file_analyses if fa.file_path.startswith("small_")]
        assert len(small_fas) == 3
        assert all(fa.skip_reason is None for fa in small_fas)
