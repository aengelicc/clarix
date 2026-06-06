"""Tests for the framework-specific system prompt registry.

Covers:
- The dispatcher (empty / single / multiple / unknown id / case)
- That framework blocks are *content-distinct* so the LLM actually gets
  framework-specific guidance (catches a copy-paste regression)
- End-to-end: LLMClient.analyze_file / analyze_bundle / synthesize_project
  prepend the framework block to the system prompt
- Analyzer wiring: unknown framework fails fast at construction
"""
import pytest

from app.services import framework_prompts

# ---------------------------------------------------------------------------
# Registry surface
# ---------------------------------------------------------------------------


def test_list_frameworks_returns_six_ids():
    ids = framework_prompts.list_frameworks()
    assert set(ids) == {"hipaa", "pci", "soc2", "gdpr", "owasp", "cis"}
    # Must be sorted for stable UI / API ordering.
    assert ids == sorted(ids)


def test_every_framework_has_substantive_instructions():
    """Catch a stub that has only a header line — instructions should be > 200 chars."""
    for fid in framework_prompts.list_frameworks():
        text = framework_prompts.FRAMEWORK_INSTRUCTIONS[fid]
        assert len(text) > 200, f"{fid} instructions are too short: {len(text)} chars"
        # Sanity: every block should mention its own framework name at least once
        # (whitespace-stripped, so "SOC 2" matches the "soc2" id).
        normalized = "".join(text.upper().split())
        assert fid.upper() in normalized, f"{fid} doesn't self-identify in instructions"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def test_get_framework_block_none_returns_empty_string():
    assert framework_prompts.get_framework_block(None) == ""


def test_get_framework_block_empty_list_returns_empty_string():
    assert framework_prompts.get_framework_block([]) == ""


def test_get_framework_block_filters_empty_strings():
    """A list like ['hipaa', '', '  '] should not crash on the empty entries."""
    block = framework_prompts.get_framework_block(["hipaa", "", "  "])
    assert "HIPAA" in block
    assert "expert code reviewer" in block.lower()


def test_get_framework_block_single_framework():
    block = framework_prompts.get_framework_block(["hipaa"])
    assert "HIPAA" in block
    assert "§164" in block  # HIPAA-specific citation marker
    # Single-framework header phrasing.
    assert "the HIPAA framework" in block


def test_get_framework_block_multiple_frameworks_joins_with_separator():
    block = framework_prompts.get_framework_block(["hipaa", "pci"])
    assert "HIPAA" in block
    assert "PCI" in block
    # Multi-framework header phrasing.
    assert "these compliance frameworks" in block.lower()
    # Bodies are joined with `---` (one between bodies, one trailing).
    assert block.count("---") >= 2


def test_get_framework_block_normalizes_case():
    block = framework_prompts.get_framework_block(["HIPAA", "Pci"])
    assert "HIPAA" in block
    assert "PCI" in block


def test_get_framework_block_unknown_raises_value_error():
    with pytest.raises(ValueError, match="Unknown framework"):
        framework_prompts.get_framework_block(["hipaa", "nist-800-53"])


def test_get_framework_block_known_ids_in_error_message():
    """The error message should list valid ids so the user can self-correct."""
    with pytest.raises(ValueError) as excinfo:
        framework_prompts.get_framework_block(["bogus"])
    msg = str(excinfo.value)
    for fid in framework_prompts.list_frameworks():
        assert fid in msg


# ---------------------------------------------------------------------------
# Content distinctness — different frameworks must produce different text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fid", framework_prompts.list_frameworks())
def test_framework_blocks_are_distinct_from_each_other(fid):
    """Each framework's instructions should be unique (no copy-paste stubs)."""
    target = framework_prompts.FRAMEWORK_INSTRUCTIONS[fid]
    for other in framework_prompts.list_frameworks():
        if other == fid:
            continue
        other_text = framework_prompts.FRAMEWORK_INSTRUCTIONS[other]
        # First 200 chars are a safe fingerprint (headers tend to differ
        # early; bodies are framework-specific throughout).
        assert target[:200] != other_text[:200], (
            f"{fid} and {other} share the first 200 chars — likely a copy-paste"
        )


# ---------------------------------------------------------------------------
# LLMClient integration — framework block is prepended to the system prompt
# ---------------------------------------------------------------------------


def _build_client():
    """Build an LLMClient that bypasses SDK init and records the system prompt."""
    from app.services.llm import LLMClient

    client = LLMClient.__new__(LLMClient)
    client.provider = "anthropic"
    client.model = "claude-test"
    client.api_key = "test"

    captured: dict = {}

    class _StubMessages:
        def create(self, **kwargs):  # noqa: ARG002
            captured["system"] = kwargs.get("system", "")
            class _C:
                text = "stub"
            class _M:
                content = [_C()]
            return _M()

    client.client = type("_C", (), {"messages": _StubMessages()})()
    return client, captured


def test_analyze_file_no_frameworks_keeps_canonical_system_prompt():
    """Regression guard: with no frameworks, the system prompt is unchanged
    from the pre-frameworks-prompt version (so existing LLM cache entries
    from before this commit remain valid)."""
    client, captured = _build_client()
    client.analyze_file("a.py", "python", "x = 1")
    sys_prompt = captured["system"]
    # Canonical opening from the original generic prompt.
    assert sys_prompt.startswith(
        "You are an expert code reviewer with 15 years of experience in "
        "software engineering, security, and performance optimization."
    )


def test_analyze_file_with_hipaa_prepends_framework_block():
    client, captured = _build_client()
    client.analyze_file("a.py", "python", "x = 1", frameworks=["hipaa"])
    sys_prompt = captured["system"]
    # Framework block comes first.
    assert sys_prompt.startswith(
        "You are an expert code reviewer focused on the HIPAA framework."
    )
    assert "§164" in sys_prompt
    # The original generic prompt's opening is still present (now the body
    # of the system prompt, after the framework block).
    assert "15 years of experience" in sys_prompt


def test_analyze_file_with_two_frameworks_combines_them():
    client, captured = _build_client()
    client.analyze_file("a.py", "python", "x = 1", frameworks=["hipaa", "pci"])
    sys_prompt = captured["system"]
    assert "HIPAA" in sys_prompt
    assert "PCI" in sys_prompt
    assert "§164" in sys_prompt  # HIPAA marker
    assert "Req 3" in sys_prompt  # PCI marker
    # Multi-framework header phrasing.
    assert "these compliance frameworks" in sys_prompt.lower()


def test_analyze_file_unknown_framework_raises_value_error():
    client, _captured = _build_client()
    with pytest.raises(ValueError, match="Unknown framework"):
        client.analyze_file("a.py", "python", "x = 1", frameworks=["bogus"])


def test_analyze_bundle_prepends_framework_block():
    client, captured = _build_client()
    client.analyze_bundle([{"path": "a.py", "language": "python", "content": "x = 1"}], frameworks=["owasp"])
    sys_prompt = captured["system"]
    assert "OWASP" in sys_prompt
    assert "A01" in sys_prompt  # OWASP-specific category


def test_synthesize_project_prepends_framework_block():
    client, captured = _build_client()
    client.synthesize_project([], [], frameworks=["soc2"])
    sys_prompt = captured["system"]
    assert "SOC2" in sys_prompt or "SOC 2" in sys_prompt.upper().replace("SOC2", "SOC 2")
    assert "CC6" in sys_prompt  # SOC 2 specific control


# ---------------------------------------------------------------------------
# Analyzer wiring
# ---------------------------------------------------------------------------


def test_code_analyzer_accepts_frameworks_param():
    """`frameworks` is wired through to every LLM call site."""
    from app.services.analyzer import CodeAnalyzer
    analyzer = CodeAnalyzer(llm_client=None, frameworks=["hipaa", "pci"])
    assert analyzer.frameworks == ["hipaa", "pci"]


def test_code_analyzer_rejects_unknown_framework_at_construction():
    """Fail fast — bad framework id should raise at construction, not mid-analysis."""
    from app.services.analyzer import CodeAnalyzer
    with pytest.raises(ValueError, match="Unknown framework"):
        CodeAnalyzer(llm_client=None, frameworks=["hipaa", "nist-800-53"])


def test_code_analyzer_defaults_frameworks_to_empty_list():
    from app.services.analyzer import CodeAnalyzer
    analyzer = CodeAnalyzer(llm_client=None)
    assert analyzer.frameworks == []


def test_analyze_request_accepts_frameworks_field():
    """API surface: AnalyzeRequest can carry a frameworks list."""
    from app.core.models import AnalyzeRequest
    req = AnalyzeRequest(
        source="https://github.com/foo/bar",
        source_type="github",
        frameworks=["hipaa"],
    )
    assert req.frameworks == ["hipaa"]
