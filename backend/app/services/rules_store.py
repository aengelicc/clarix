"""Persistent store for security scanning rules (built-in + custom)."""
import json
import re
import threading
import uuid
from pathlib import Path
from typing import List, Optional

from app.core.models import SecurityRule, SecurityRuleCreate, SecurityRuleUpdate

DATA_FILE = Path(__file__).parent.parent / "data" / "rules.json"

_cache: Optional[List[SecurityRule]] = None
_cache_mtime: float = 0.0
_lock = threading.RLock()


def _save(rules: List[SecurityRule]) -> None:
    global _cache, _cache_mtime
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with open(DATA_FILE, "w") as f:
            json.dump([r.model_dump(mode="json") for r in rules], f, indent=2)
        _cache = rules
        _cache_mtime = DATA_FILE.stat().st_mtime


def _seed() -> None:
    # Lazy imports to avoid circular dependency (scanners import rules_store).
    from app.services.security import SECRET_PATTERNS, DANGEROUS_PATTERNS
    from app.services.hipaa import HIPAA_PATTERNS
    from app.services.pci_dss import PCI_PATTERNS
    from app.services.gdpr import GDPR_PATTERNS
    from app.services.soc2 import SOC2_PATTERNS

    rules: List[SecurityRule] = []

    for i, (name, pattern, severity) in enumerate(SECRET_PATTERNS):
        rules.append(SecurityRule(
            id=f"sec-secret-{i:03d}",
            name=name,
            pattern=pattern,
            severity=severity,
            description=f"Potential secret detected: {name}. This may be a hardcoded credential.",
            recommendation="Move secrets to environment variables or a secure vault. Never commit credentials to version control.",
            language="*",
            scanner="security",
            rule_type="secret",
        ))

    j = 0
    for language, patterns in DANGEROUS_PATTERNS.items():
        for pattern, description, severity in patterns:
            rules.append(SecurityRule(
                id=f"sec-danger-{j:03d}",
                name=f"{description[:60].rstrip()}",
                pattern=pattern,
                severity=severity,
                description=description,
                recommendation="Review this code path and sanitize all inputs. Consider safer alternatives.",
                language=language,
                scanner="security",
                rule_type="dangerous",
            ))
            j += 1

    for i, (name, pattern, severity, ref, recommendation) in enumerate(HIPAA_PATTERNS):
        rules.append(SecurityRule(
            id=f"hipaa-{i:03d}",
            name=name,
            pattern=pattern,
            severity=severity,
            description=f"{name} — {ref}.",
            recommendation=recommendation,
            language="*",
            scanner="hipaa",
            rule_type="compliance",
            compliance_ref=ref,
        ))

    for i, (name, pattern, severity, ref, recommendation) in enumerate(PCI_PATTERNS):
        rules.append(SecurityRule(
            id=f"pci-{i:03d}",
            name=name,
            pattern=pattern,
            severity=severity,
            description=f"{name} — {ref}.",
            recommendation=recommendation,
            language="*",
            scanner="pci",
            rule_type="compliance",
            compliance_ref=ref,
        ))

    for i, (name, pattern, severity, ref, recommendation) in enumerate(GDPR_PATTERNS):
        rules.append(SecurityRule(
            id=f"gdpr-{i:03d}",
            name=name,
            pattern=pattern,
            severity=severity,
            description=f"{name} — {ref}.",
            recommendation=recommendation,
            language="*",
            scanner="gdpr",
            rule_type="compliance",
            compliance_ref=ref,
        ))

    for i, (name, pattern, severity, ref, recommendation) in enumerate(SOC2_PATTERNS):
        rules.append(SecurityRule(
            id=f"soc2-{i:03d}",
            name=name,
            pattern=pattern,
            severity=severity,
            description=f"{name} — {ref}.",
            recommendation=recommendation,
            language="*",
            scanner="soc2",
            rule_type="compliance",
            compliance_ref=ref,
        ))

    _save(rules)


def _load() -> List[SecurityRule]:
    global _cache, _cache_mtime
    with _lock:
        if not DATA_FILE.exists():
            _seed()
            return _cache  # type: ignore[return-value]
        mtime = DATA_FILE.stat().st_mtime
        if _cache is not None and mtime == _cache_mtime:
            return _cache
        with open(DATA_FILE) as f:
            data = json.load(f)
        _cache = [SecurityRule(**r) for r in data]
        _cache_mtime = mtime
        return _cache


def get_all_rules() -> List[SecurityRule]:
    return _load()


def get_active_rules(scanner: Optional[str] = None, rule_type: Optional[str] = None) -> List[SecurityRule]:
    rules = [r for r in _load() if r.enabled]
    if scanner:
        rules = [r for r in rules if r.scanner == scanner]
    if rule_type:
        rules = [r for r in rules if r.rule_type == rule_type]
    return rules


def _validate_pattern(pattern: str) -> None:
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex: {exc}") from exc
    # Test against a pathological input to catch catastrophic backtracking (ReDoS).
    done = threading.Event()
    def _probe():
        compiled.search("a" * 5000)
        done.set()
    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    if not done.wait(timeout=1.0):
        raise ValueError("Pattern rejected: timed out on test input (potential ReDoS)")


def add_rule(create: SecurityRuleCreate) -> SecurityRule:
    _validate_pattern(create.pattern)
    rules = _load()
    rule = SecurityRule(id=str(uuid.uuid4()), builtin=False, **create.model_dump())
    rules.append(rule)
    _save(rules)
    return rule


def update_rule(rule_id: str, update: SecurityRuleUpdate) -> SecurityRule:
    rules = _load()
    for i, rule in enumerate(rules):
        if rule.id == rule_id:
            patch = update.model_dump(exclude_none=True)
            if "pattern" in patch:
                _validate_pattern(patch["pattern"])
            updated = SecurityRule(**{**rule.model_dump(), **patch})
            rules[i] = updated
            _save(rules)
            return updated
    raise KeyError(rule_id)


def delete_rule(rule_id: str) -> None:
    rules = _load()
    target = next((r for r in rules if r.id == rule_id), None)
    if target is None:
        raise KeyError(rule_id)
    if target.builtin:
        raise ValueError(f"Built-in rule '{rule_id}' cannot be deleted; use update to disable it.")
    _save([r for r in rules if r.id != rule_id])


def bulk_update_enabled(enabled: bool) -> List[SecurityRule]:
    rules = _load()
    updated = [SecurityRule(**{**r.model_dump(), "enabled": enabled}) for r in rules]
    _save(updated)
    return updated
