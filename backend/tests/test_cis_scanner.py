"""Smoke tests for the CIS Critical Security Controls v8 scanner."""
import pytest

from app.services.cis_controls import scan_cis


@pytest.fixture
def rel_path(tmp_path):
    f = tmp_path / "test.py"
    return str(f.relative_to(tmp_path))


def _scan(content: str, rel: str):
    return scan_cis(file_path=rel, relative_path=rel, language="Python", content=content)


def test_weak_hash_fires(rel_path):
    content = "digest = hashlib.md5(b'data').hexdigest()\n"
    issues = _scan(content, rel_path)
    assert any("CIS v8 16" in (i.compliance_ref or "") for i in issues), issues


def test_pickle_loads_fires(rel_path):
    content = "data = pickle.loads(buf)\n"
    issues = _scan(content, rel_path)
    assert any("CIS v8 16" in (i.compliance_ref or "") for i in issues), issues


def test_path_traversal_concat_fires(rel_path):
    content = "with open('/var/data/' + filename, 'r') as f: data = f.read()\n"
    issues = _scan(content, rel_path)
    assert any("CIS v8 16" in (i.compliance_ref or "") for i in issues), issues


def test_open_redirect_fires(rel_path):
    content = "return redirect(request.GET['next'])\n"
    issues = _scan(content, rel_path)
    assert any("CIS v8 16" in (i.compliance_ref or "") for i in issues), issues


def test_silent_except_multiline(rel_path):
    # Multi-line pattern: must fire even though 'except' and 'pass' are on different lines.
    content = "try:\n    risky()\nexcept Exception:\n    pass\n"
    issues = _scan(content, rel_path)
    assert any("CIS v8 8" in (i.compliance_ref or "") for i in issues), issues


def test_privileged_op_without_audit_multiline(rel_path):
    content = "def delete_user(user_id):\n    User.objects.filter(id=user_id).delete()\n"
    issues = _scan(content, rel_path)
    assert any("CIS v8 8" in (i.compliance_ref or "") for i in issues), issues


def test_cis_checklist_section_mapping():
    from app.services.cis_controls import build_cis_checklist
    from app.core.models import Issue, Severity, Category

    issue = Issue(
        category=Category.SECURITY,
        severity=Severity.HIGH,
        file="x.py",
        line=1,
        description="x",
        recommendation="y",
        compliance_ref="CIS v8 16.10 (IG2)",
        source="cis_scanner",
    )
    cl = build_cis_checklist([issue])
    s16 = next((c for c in cl if c.section == "16.x"), None)
    assert s16 is not None
    assert s16.status == "fail"
    assert s16.findings_count == 1


def test_cis_pattern_count_matches_module():
    from app.services.cis_controls import CIS_PATTERNS
    from app.services import rules_store
    rules = rules_store.get_active_rules(scanner="cis")
    assert len(rules) == len(CIS_PATTERNS)
