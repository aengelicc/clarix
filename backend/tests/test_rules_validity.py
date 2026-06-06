"""Validate that every pattern in the built-in rules.json is a compilable regex
that doesn't trigger the ReDoS timeout probe in rules_store._validate_pattern.

Catches broken patterns before they reach a scan.
"""
import re
import threading

from app.services import rules_store


def _validates(pattern: str) -> None:
    """Replicates rules_store._validate_pattern but doesn't raise on success."""
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise AssertionError(f"Pattern did not compile: {exc}\n  pattern: {pattern!r}") from exc
    done = threading.Event()

    def _probe():
        compiled.search("a" * 5000)
        done.set()

    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    if not done.wait(timeout=1.0):
        raise AssertionError(
            f"Pattern timed out on ReDoS probe (likely catastrophic backtracking):\n  pattern: {pattern!r}"
        )


def test_every_builtin_rule_pattern_is_valid_regex():
    rules = rules_store.get_all_rules()
    assert len(rules) >= 100, f"Expected >= 100 rules after the framework expansion, got {len(rules)}"
    for rule in rules:
        _validates(rule.pattern)


def test_all_seven_scanners_are_seeded():
    rules = rules_store.get_all_rules()
    scanners = {r.scanner for r in rules}
    expected = {"security", "hipaa", "pci", "gdpr", "soc2", "owasp", "cis"}
    assert scanners >= expected, f"Missing scanners: {expected - scanners}"


def test_every_rule_has_unique_id():
    rules = rules_store.get_all_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {[i for i in ids if ids.count(i) > 1]}"


def test_every_rule_has_required_fields():
    rules = rules_store.get_all_rules()
    for rule in rules:
        assert rule.name.strip(), f"Empty name on {rule.id}"
        assert rule.description.strip(), f"Empty description on {rule.id}"
        assert rule.recommendation.strip(), f"Empty recommendation on {rule.id}"
        assert rule.severity.value in {"critical", "high", "medium", "low", "info"}, (
            f"Bad severity on {rule.id}: {rule.severity}"
        )
