"""Generic static-rule scanner used by all framework scanners (security, hipaa,
pci, gdpr, soc2, owasp, cis).

Each scanner module used to have its own near-identical loop: read enabled
rules from rules_store, iterate lines, build Issues, handle multi-line
patterns, skip comments. This module consolidates that logic so the
per-framework scanner modules are just seed data (PATTERNS list +
CHECKLIST_TEMPLATE) plus a one-line scan() shim.

Behaviour-preserving: each scanner's previous quirks (security's
case-insensitive comment skip, multi-line pattern handling in
gdpr/soc2/owasp/cis) are exposed as parameters.
"""
from __future__ import annotations

import re

from app.core.models import Category, Issue
from app.services import rules_store

# Comment prefixes that mark a line as documentation rather than live code.
COMMENT_PREFIXES: tuple = ("#", "//", "*", "<!--")


def _is_comment_line(stripped: str) -> bool:
    return any(stripped.startswith(p) for p in COMMENT_PREFIXES)


def _build_issue(rule, source: str, relative_path: str, line: int,
                code_snippet: str | None = None) -> Issue:
    """Build a single Issue from a matching rule. The hipaa scanner is the
    only one that uses the hipaa_reference field; the others just set
    compliance_ref (which the API serializes as the 'compliance' badge)."""
    is_hipaa = source == "hipaa_scanner"
    return Issue(
        category=Category.SECURITY,
        severity=rule.severity,
        file=relative_path,
        line=line,
        description=rule.description,
        recommendation=rule.recommendation,
        compliance_ref=rule.compliance_ref,
        hipaa_reference=rule.compliance_ref if is_hipaa else None,
        code_snippet=code_snippet,
        source=source,
        rule_id=rule.id,
    )


def scan_rules(
    relative_path: str,
    language: str,
    content: str,
    *,
    scanner: str,
    rule_type: str | None = None,
    source: str | None = None,
    language_check: bool = True,
    comment_strip_lower: bool = False,
) -> list[Issue]:
    """Run a static rule scan and return matched Issues.

    Args:
        relative_path: file path relative to the repo root (for Issue.file).
        language: detected language of the file (e.g. "Python", "JavaScript").
        content: full file contents.
        scanner: scanner identifier used to look up enabled rules
            (e.g. "security", "hipaa", "owasp", "cis").
        rule_type: optional filter on rule.rule_type (e.g. "secret",
            "dangerous", "compliance"). None means "all enabled rules".
        source: override the source label on resulting Issues. Default
            is f"{scanner}_scanner" to match the original per-scanner labels.
        language_check: if True, only apply a rule when its `language`
            matches the file (or is "*"). The security/secret loop doesn't
            check language — set this False to mirror that.
        comment_strip_lower: if True, skip a line if its lowercased
            stripped form starts with any comment prefix. The original
            security/secret loop does this so an uppercase comment like
            "# AWS KEY" is treated as documentation.
    """
    source = source or f"{scanner}_scanner"
    issues: list[Issue] = []
    lines = content.splitlines()
    rules = rules_store.get_active_rules(scanner=scanner, rule_type=rule_type)

    for rule in rules:
        # Multi-line patterns: match against the full content with
        # multiline+dotall so patterns containing \n work correctly.
        if "\\n" in rule.pattern or "\n" in rule.pattern:
            m = re.search(rule.pattern, content, re.MULTILINE | re.DOTALL)
            if not m:
                continue
            line_num = content[: m.start()].count("\n") + 1
            issues.append(_build_issue(rule, source, relative_path, line_num))
            continue

        # Per-line patterns: language filter (when enabled) runs once per rule.
        if language_check and rule.language not in ("*", language):
            continue

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if comment_strip_lower:
                if stripped.lower().startswith(COMMENT_PREFIXES):
                    continue
            else:
                if _is_comment_line(stripped):
                    continue
            if re.search(rule.pattern, line):
                issues.append(_build_issue(
                    rule, source, relative_path, i,
                    code_snippet=stripped[:150],
                ))
    return issues
