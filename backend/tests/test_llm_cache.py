"""Tests for the in-process LLM response cache.

Covers the three behaviours that matter:
- cache hit returns the stored response without invoking the provider
- different inputs (content / model / provider) miss
- TTL expiry, max-entries eviction, and `llm_cache_enabled=False` disable
"""
import time

import pytest

from app.core import config
from app.services import llm_cache


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test starts with an empty cache and zeroed stats."""
    llm_cache.clear()
    llm_cache.reset_stats()
    yield
    llm_cache.clear()


# ---------------------------------------------------------------------------
# Pure module-level tests — no LLMClient involved.
# ---------------------------------------------------------------------------


def test_miss_returns_none():
    result = llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096)
    assert result is None


def test_set_then_get_round_trips():
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user", 4096, "response text")
    result = llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096)
    assert result == "response text"


def test_different_user_prompt_is_miss():
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user-A", 4096, "A response")
    result = llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user-B", 4096)
    assert result is None


def test_different_system_prompt_is_miss():
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys-A", "user", 4096, "A response")
    result = llm_cache.get("anthropic", "claude-sonnet-4-6", "sys-B", "user", 4096)
    assert result is None


def test_different_model_is_miss():
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user", 4096, "anthropic response")
    result = llm_cache.get("openai", "gpt-4o", "sys", "user", 4096)
    assert result is None


def test_different_max_tokens_is_miss():
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user", 4096, "r")
    result = llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 8192)
    assert result is None


def test_disabled_cache_is_no_op(monkeypatch):
    monkeypatch.setattr(config.settings, "llm_cache_enabled", False)
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user", 4096, "response")
    assert llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096) is None
    # Disabled set() must not consume a slot either
    assert llm_cache.size() == 0


def test_prompt_version_busts_cache():
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user", 4096, "v1 response")
    original_version = llm_cache.PROMPT_VERSION
    try:
        llm_cache.PROMPT_VERSION = "v2"
        assert llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096) is None
    finally:
        llm_cache.PROMPT_VERSION = original_version


def test_ttl_expiry_evicts_entry():
    # Plant a stale entry directly so we don't have to sleep through the real TTL.
    key = llm_cache._make_key("anthropic", "claude-sonnet-4-6", "sys", "user", 4096)
    with llm_cache._lock:
        llm_cache._cache[key] = (time.time() - 1.0, "old response")
    result = llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096)
    assert result is None
    assert llm_cache.size() == 0
    # Eviction should be reflected in stats.
    assert llm_cache.stats()["evictions"] >= 1


def test_max_entries_evicts_oldest(monkeypatch):
    monkeypatch.setattr(config.settings, "llm_cache_max_entries", 2)
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user-1", 4096, "r1")
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user-2", 4096, "r2")
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user-3", 4096, "r3")
    assert llm_cache.size() == 2
    # user-1 was the oldest — it should be gone.
    assert llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user-1", 4096) is None
    assert llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user-2", 4096) == "r2"
    assert llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user-3", 4096) == "r3"


def test_stats_track_hits_misses_and_stores():
    # miss (no entry)
    llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "no-such-key", 4096)
    # miss (still no entry after the set below? no — set first, then get)
    llm_cache.set("anthropic", "claude-sonnet-4-6", "sys", "user", 4096, "r")
    # hit
    llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096)
    # another hit
    llm_cache.get("anthropic", "claude-sonnet-4-6", "sys", "user", 4096)
    s = llm_cache.stats()
    assert s["misses"] == 1
    assert s["hits"] == 2
    assert s["stores"] == 1


# ---------------------------------------------------------------------------
# Integration: LLMClient._call_llm consults the cache.
# ---------------------------------------------------------------------------


def _build_client_with_stub_provider():
    """Build an LLMClient that bypasses the real SDK init and counts provider calls.

    Returns (client, messages_stub) where `messages_stub` records every
    call to the (fake) provider's `messages.create(...)` method.
    """
    from app.services.llm import LLMClient

    client = LLMClient.__new__(LLMClient)
    client.provider = "anthropic"
    client.model = "claude-test"
    client.api_key = "test"

    class _StubMessages:
        def __init__(self):
            self.call_count = 0

        def create(self, **kwargs):  # noqa: ARG002 — interface parity with anthropic.Anthropic
            self.call_count += 1

            class _Content:
                text = "fake-response-text"

            class _Message:
                content = [_Content()]

            return _Message()

    class _StubAnthropicClient:
        def __init__(self):
            self.messages = _StubMessages()

    client.client = _StubAnthropicClient()
    return client, client.client.messages


def test_call_llm_caches_response_on_second_call():
    client, messages = _build_client_with_stub_provider()

    r1 = client._call_llm("sys", "user-1", 4096)
    r2 = client._call_llm("sys", "user-1", 4096)  # same args → cache hit

    assert r1 == "fake-response-text"
    assert r2 == "fake-response-text"
    # Provider should have been invoked exactly once.
    assert messages.call_count == 1


def test_call_llm_different_content_misses_cache():
    client, messages = _build_client_with_stub_provider()

    client._call_llm("sys", "user-A", 4096)
    client._call_llm("sys", "user-B", 4096)  # different content → real call

    assert messages.call_count == 2


def test_call_llm_disabled_cache_invokes_provider_every_time(monkeypatch):
    monkeypatch.setattr(config.settings, "llm_cache_enabled", False)
    client, messages = _build_client_with_stub_provider()

    client._call_llm("sys", "user-1", 4096)
    client._call_llm("sys", "user-1", 4096)
    client._call_llm("sys", "user-1", 4096)

    # Cache disabled → 3 real calls.
    assert messages.call_count == 3


def test_analyze_file_returns_cached_result_on_second_call(monkeypatch):
    """End-to-end: analyze_file caches the parsed result via the underlying _call_llm."""
    client, messages = _build_client_with_stub_provider()

    # analyze_file calls _call_llm internally. The stub returns
    # "fake-response-text" which is not valid JSON, so analyze_file should
    # return its parse-error fallback dict. We just want to verify that the
    # second call is a cache hit and so does NOT increment messages.call_count.
    r1 = client.analyze_file("a.py", "python", "x = 1")
    r2 = client.analyze_file("a.py", "python", "x = 1")

    assert r1 == r2
    assert messages.call_count == 1
