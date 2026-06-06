"""In-process TTL cache for LLM responses.

Why: identical file content sent to the LLM produces an identical response
(deterministic for a given provider + model + prompt + temperature). When the
same code is scanned multiple times in development, the analyzer burns real
API credits re-running the same call. This module short-circuits that.

Scope: in-memory only. Single-process. Lost on restart — that's a feature
during dev (we always want a fresh result on a fresh server). If we ever
need cross-process persistence, swap the dict for SQLite or Redis without
touching the public API.

Concurrency: a `threading.RLock` guards the dict. The analysis pipeline
runs LLM calls inside a worker thread (see `api/analysis.py`); the cache
is shared across requests, so the lock is process-wide. `RLock` matches
the pattern in `rules_store.py` and is safe against re-entry.

Cache key: SHA-256 hash of `(PROMPT_VERSION, provider, model, max_tokens,
system_prompt, user_prompt)`. We hash the full prompts (not just the user
prompt) so a future prompt-template change is reflected in the key
automatically, but we also expose `PROMPT_VERSION` as a manual kill-switch
to flush all entries without restarting the server.
"""
from __future__ import annotations

import hashlib
import threading
import time

# Bump this whenever the system prompts in `llm.py` change in a way that
# would change the LLM's output for the same input. Bumping forces a clean
# miss on the next call; the old entries age out via TTL.
PROMPT_VERSION = "v1"

_cache: dict[str, tuple[float, str]] = {}  # key -> (expires_at_unix_ts, response_text)
_lock = threading.RLock()
_stats = {"hits": 0, "misses": 0, "stores": 0, "evictions": 0}


def _make_key(provider: str, model: str, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
    """Hash the cache inputs. Order-sensitive; do not reorder fields."""
    h = hashlib.sha256()
    h.update(PROMPT_VERSION.encode("utf-8"))
    h.update(b"\0")
    h.update(provider.encode("utf-8"))
    h.update(b"\0")
    h.update(model.encode("utf-8"))
    h.update(b"\0")
    h.update(str(max_tokens).encode("utf-8"))
    h.update(b"\0")
    h.update(system_prompt.encode("utf-8"))
    h.update(b"\0")
    h.update(user_prompt.encode("utf-8"))
    return h.hexdigest()


def _is_enabled() -> bool:
    # Lazy import to avoid a hard dependency on Settings at import time
    # (useful when this module is imported in unit tests before app boot).
    from app.core.config import settings

    return bool(settings.llm_cache_enabled)


def _ttl_seconds() -> int:
    from app.core.config import settings

    return int(settings.llm_cache_ttl_seconds)


def _max_entries() -> int:
    from app.core.config import settings

    return int(settings.llm_cache_max_entries)


def get(
    provider: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
) -> str | None:
    """Return a cached response_text for these args, or None on miss / disabled / expired."""
    if not _is_enabled():
        return None
    key = _make_key(provider, model, system_prompt, user_prompt, max_tokens)
    now = time.time()
    with _lock:
        entry = _cache.get(key)
        if entry is None:
            _stats["misses"] += 1
            return None
        expires_at, response_text = entry
        if expires_at < now:
            del _cache[key]
            _stats["evictions"] += 1
            _stats["misses"] += 1
            return None
        _stats["hits"] += 1
        return response_text


def set(
    provider: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    response_text: str,
) -> None:
    """Store response_text under these args. No-op if cache is disabled."""
    if not _is_enabled():
        return
    key = _make_key(provider, model, system_prompt, user_prompt, max_tokens)
    expires_at = time.time() + _ttl_seconds()
    with _lock:
        if len(_cache) >= _max_entries():
            # Simple LRU-by-expiry: drop the entry with the earliest expires_at.
            # Good enough for a dev-grade cache; if we ever need true LRU we'd
            # swap in `collections.OrderedDict` or `functools.lru_cache`.
            oldest_key = min(_cache, key=lambda k: _cache[k][0])
            del _cache[oldest_key]
            _stats["evictions"] += 1
        _cache[key] = (expires_at, response_text)
        _stats["stores"] += 1


def clear() -> None:
    """Drop every entry. Useful for tests."""
    with _lock:
        _cache.clear()


def size() -> int:
    with _lock:
        return len(_cache)


def stats() -> dict:
    with _lock:
        return dict(_stats)


def reset_stats() -> None:
    with _lock:
        for k in _stats:
            _stats[k] = 0
