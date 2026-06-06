"""Smoke tests for the existing security scanner plus the new gap-fill rules."""
import pytest

from app.services.security import scan_file


@pytest.fixture
def rel_path(tmp_path):
    f = tmp_path / "test.py"
    return str(f.relative_to(tmp_path))


def _scan(content: str, rel: str, lang: str = "Python"):
    return scan_file(file_path=rel, relative_path=rel, language=lang, content=content)


def test_aws_access_key_still_fires(rel_path):
    content = "AKIAIOSFODNN7EXAMPLE\n"
    issues = _scan(content, rel_path)
    assert any("AWS Access Key" in i.description for i in issues)


def test_openai_key_gap_fill_fires(rel_path):
    # Single contiguous sk-... string (not split by concat) so it doesn't also match AWS Secret Key.
    content = "openai.api_key = 'sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n"
    issues = _scan(content, rel_path)
    assert any("OpenAI" in i.description for i in issues), issues


def test_anthropic_key_gap_fill_fires(rel_path):
    content = "client = anthropic.Anthropic(api_key='sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890')\n"
    issues = _scan(content, rel_path)
    assert any("Anthropic" in i.description for i in issues), issues


def test_jwt_literal_gap_fill_fires(rel_path):
    # Two valid base64url segments separated by dots — looks like a real JWT.
    content = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue123"\n'
    issues = _scan(content, rel_path)
    assert any("JWT" in i.description for i in issues), issues


def test_azure_storage_gap_fill_fires(rel_path):
    content = 'conn = "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCD=="\n'
    issues = _scan(content, rel_path)
    assert any("Azure" in i.description for i in issues), issues


def test_gcp_api_key_gap_fill_fires(rel_path):
    content = 'gmaps = googlemaps.Client(key="AIzaSyA-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")\n'
    issues = _scan(content, rel_path)
    assert any("Google Cloud" in i.description for i in issues), issues
