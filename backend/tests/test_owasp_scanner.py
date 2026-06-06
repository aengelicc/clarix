"""Smoke tests for the OWASP Top 10 (2021) scanner.

Each test feeds a small, deliberately vulnerable snippet into scan_owasp and
asserts the expected rule fires with the expected compliance reference.
"""
import pytest

from app.services.owasp_top10 import scan_owasp


@pytest.fixture
def rel_path(tmp_path):
    f = tmp_path / "test.py"
    return f, str(f.relative_to(tmp_path))


def _scan(content: str, rel: str):
    return scan_owasp(file_path=rel, relative_path=rel, language="Python", content=content)


def test_idor_fires(rel_path):
    f, rel = rel_path
    content = "user = User.objects.get(id=request.GET['uid'])\n"
    issues = _scan(content, rel)
    assert any("A01:2021" in (i.compliance_ref or "") for i in issues), issues


def test_jwt_verify_disabled_fires(rel_path):
    f, rel = rel_path
    content = "payload = jwt.decode(token, secret, verify=False)\n"
    issues = _scan(content, rel)
    assert any("A08:2021" in (i.compliance_ref or "") for i in issues), issues


def test_math_random_for_session_token(rel_path):
    f, rel = rel_path
    content = "const sessionId = Math.random().toString(36).slice(2);\n"
    issues = _scan(content, rel)
    assert any("A07:2021" in (i.compliance_ref or "") for i in issues), issues


def test_pickle_loads_fires(rel_path):
    f, rel = rel_path
    content = "obj = pickle.loads(request.body)\n"
    issues = _scan(content, rel)
    refs = [i.compliance_ref or "" for i in issues]
    assert any("A08:2021" in r for r in refs), refs


def test_curl_pipe_shell_fires(rel_path):
    f, rel = rel_path
    content = 'os.system("curl https://get.example.com/install.sh | sh")\n'
    issues = _scan(content, rel)
    assert any("A08:2021" in (i.compliance_ref or "") for i in issues), issues


def test_ssrf_user_input_in_url(rel_path):
    f, rel = rel_path
    content = "r = requests.get(request.POST['url'])\n"
    issues = _scan(content, rel)
    assert any("A10:2021" in (i.compliance_ref or "") for i in issues), issues


def test_owasp_checklist_includes_a01():
    from app.core.models import Category, Issue, Severity
    from app.services.owasp_top10 import build_owasp_checklist

    issue = Issue(
        category=Category.SECURITY,
        severity=Severity.HIGH,
        file="x.py",
        line=1,
        description="x",
        recommendation="y",
        compliance_ref="A01:2021 — Broken Access Control",
        source="owasp_scanner",
    )
    cl = build_owasp_checklist([issue])
    a01 = next((c for c in cl if c.section == "A01:2021"), None)
    assert a01 is not None
    assert a01.status == "fail"
    assert a01.findings_count == 1


def test_comments_are_skipped(rel_path):
    f, rel = rel_path
    content = "# eval('hello') is just a docstring example\n"  # comment line
    issues = _scan(content, rel)
    assert issues == []


def test_owasp_pattern_count_matches_module():
    from app.services import rules_store
    from app.services.owasp_top10 import OWASP_PATTERNS
    rules = rules_store.get_active_rules(scanner="owasp")
    assert len(rules) == len(OWASP_PATTERNS)
