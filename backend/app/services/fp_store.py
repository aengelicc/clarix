"""False-positive tracking store.

Why this exists: the LLM (and the static scanners) sometimes flag things
that aren't actually problems — a test fixture, a vendor pattern that
looks like a credential but isn't, a "TODO" that the team already
knows about. Without a way to mark these, every scan is full of
recurring noise. This module persists FP marks so subsequent scans
filter them out.

Storage:
- A JSON file at `~/.clarix/fp_marks.json` (configurable via env).
  Matches the rules.json pattern in `rules_store.py` — same locking
  discipline, same mtime-based cache invalidation, same hand-rolled
  shape so the file is inspectable by hand.

Mark schema:
  {
    "marks": [
      {
        "id": "uuid4",
        "file_path": "src/auth.py",
        "rule_id": "sec-secret-001" | null,        # static scanner: rule_id
        "description_hash": "sha256:..." | null,   # LLM-detected: hash of description
        "reason": "Reviewed; this is a test fixture",
        "marked_at": "2026-06-06T10:00:00+00:00",
        "marked_by": "user"
      }
    ]
  }

A mark is considered to "match" an issue when:
- `file_path` matches exactly, AND
- either `rule_id` matches (for static issues) or `description_hash`
  matches (for LLM issues). The two are not interchangeable — a mark
  is either a static-scanner FP or an LLM FP, not both.

Threading:
- A `threading.RLock` guards reads and writes, same as `rules_store`.
  The analyzer runs in a worker thread; the API can mutate from
  another thread.

Concurrency:
- The cache is process-local and lost on restart. Re-reads from disk
  on first call (mtime-based) and re-reads on mtime change. Concurrent
  reads are fine; concurrent writes are serialized by the lock.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Default location; ~/.clarix/ follows the XDG-ish pattern used by
# many CLI tools. Can be overridden via the CLARIX_FP_MARKS_FILE env var.
_DEFAULT_PATH = Path.home() / ".clarix" / "fp_marks.json"


def _marks_path() -> Path:
    override = os.environ.get("CLARIX_FP_MARKS_FILE")
    return Path(override) if override else _DEFAULT_PATH


# Cache state: (mtime, marks_list). Marks are stored in insertion order
# so GET returns a stable list.
_cache: list[dict[str, Any]] | None = None
_cache_mtime: float = 0.0
_lock = threading.RLock()


def _load() -> list[dict[str, Any]]:
    """Load marks from disk, with mtime-based cache invalidation."""
    global _cache, _cache_mtime
    path = _marks_path()
    with _lock:
        if _cache is not None:
            try:
                current_mtime = path.stat().st_mtime
            except FileNotFoundError:
                current_mtime = 0.0
            if current_mtime == _cache_mtime:
                return _cache
        return _read_from_disk(path)


def _read_from_disk(path: Path) -> list[dict[str, Any]]:
    global _cache, _cache_mtime
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        _cache = []
        _cache_mtime = 0.0
        return _cache
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        # Corrupt or unreadable — start clean rather than crash.
        _cache = []
        _cache_mtime = mtime
        return _cache
    _cache = data.get("marks", []) if isinstance(data, dict) else []
    _cache_mtime = mtime
    return _cache


def _save(marks: list[dict[str, Any]]) -> None:
    """Persist marks to disk and update the in-memory cache."""
    global _cache, _cache_mtime
    path = _marks_path()
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"marks": marks}, f, indent=2, ensure_ascii=False)
        _cache = list(marks)
        _cache_mtime = path.stat().st_mtime


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def hash_description(description: str) -> str:
    """Stable, short fingerprint for an LLM issue description.

    Used as the matching key for LLM FP marks. SHA-256 hex of the
    description, prefix `sha256:` for self-documentation.
    """
    h = hashlib.sha256(description.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def list_marks() -> list[dict[str, Any]]:
    """Return all FP marks (copy — safe to mutate)."""
    return list(_load())


def is_marked(
    file_path: str,
    rule_id: str | None = None,
    description_hash: str | None = None,
) -> bool:
    """True iff there's a mark that matches this issue.

    `rule_id` is matched against the mark's `rule_id`; `description_hash`
    is matched against the mark's `description_hash`. A mark is
    considered a match when file_path matches AND (rule_id matches OR
    description_hash matches). Both fields on the mark side are
    optional — see `add_mark` for the validation rules.
    """
    if not file_path:
        return False
    for mark in _load():
        if mark.get("file_path") != file_path:
            continue
        if rule_id is not None and mark.get("rule_id") == rule_id:
            return True
        if description_hash is not None and mark.get("description_hash") == description_hash:
            return True
    return False


def add_mark(
    file_path: str,
    reason: str = "",
    rule_id: str | None = None,
    description_hash: str | None = None,
    marked_by: str = "user",
) -> dict[str, Any]:
    """Add an FP mark and return it. Idempotent: re-adding the same
    mark (same file_path + same rule_id, or same file_path + same
    description_hash) returns the existing mark without changing it.

    Exactly one of `rule_id` or `description_hash` must be set —
    a mark is either a static-scanner FP or an LLM FP, not both.
    """
    if not file_path:
        raise ValueError("file_path is required")
    if (rule_id is None) == (description_hash is None):
        raise ValueError(
            "Exactly one of rule_id (static-scanner FP) or description_hash "
            "(LLM FP) must be set."
        )
    with _lock:
        marks = list(_load())
        for existing in marks:
            if existing.get("file_path") != file_path:
                continue
            if rule_id is not None and existing.get("rule_id") == rule_id:
                return existing
            if description_hash is not None and existing.get("description_hash") == description_hash:
                return existing
        mark = {
            "id": str(uuid.uuid4()),
            "file_path": file_path,
            "rule_id": rule_id,
            "description_hash": description_hash,
            "reason": reason,
            "marked_at": datetime.now(UTC).isoformat(),
            "marked_by": marked_by,
        }
        marks.append(mark)
        _save(marks)
        return mark


def remove_mark(mark_id: str) -> bool:
    """Remove the mark with the given id. Returns True if removed."""
    with _lock:
        marks = list(_load())
        new_marks = [m for m in marks if m.get("id") != mark_id]
        if len(new_marks) == len(marks):
            return False
        _save(new_marks)
        return True


def clear() -> None:
    """Drop every mark. Used by tests."""
    global _cache, _cache_mtime
    with _lock:
        _save([])


def size() -> int:
    return len(_load())
