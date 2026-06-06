"""SARIF 2.1.0 export for Clarix findings.

Converts a ProjectReport into a SARIF document consumable by GitHub Code
Scanning, IDE plugins, and other security tooling. Static-scanner issues
get their rule_id from rules.json; LLM-detected issues get a stable
synthetic ID derived from the report position.
"""
import re
from typing import Any

from app.core.models import Issue, ProjectReport, Severity

# SARIF 2.1.0 (latest) — https://docs.oasis-open.org/sarif/sarif/v2.1.0
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0-rtm.5.json"
CLARIX_NAME = "Clarix"
CLARIX_VERSION = "1.0.0"
CLARIX_INFO_URI = "https://github.com/aengelicc/clarix"

# Map Clarix severity -> SARIF level.
#   error   = blocker
#   warning = should fix
#   note    = informational
#   none    = not actionable
SEVERITY_TO_LEVEL: dict[str, str] = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value: "error",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "note",
    Severity.INFO.value: "none",
}


def _slugify(name: str) -> str:
    """Convert a rule name to a SARIF-friendly identifier (letters/digits/underscore)."""
    slug = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
    return slug or "Rule"


def _all_issues(report: ProjectReport) -> list[Issue]:
    issues: list[Issue] = list(report.security_findings)
    for fa in report.file_analyses:
        issues.extend(fa.issues)
    issues.extend(report.project_level_issues)
    return issues


def _build_rule_entry(
    rule_id: str,
    sample_issue: Issue,
    rule_def: Any,  # SecurityRule | None
) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (a 'rule' entry) for one rule."""
    if rule_def is not None:
        name = _slugify(rule_def.name)
        short = rule_def.name
        full = rule_def.description
        help_text = rule_def.recommendation
        default_level = SEVERITY_TO_LEVEL.get(rule_def.severity.value, "warning")
        props: dict[str, Any] = {
            "scanner": rule_def.scanner,
            "ruleType": rule_def.rule_type,
        }
        if rule_def.compliance_ref:
            props["complianceRef"] = rule_def.compliance_ref
        if rule_def.language and rule_def.language != "*":
            props["language"] = rule_def.language
    else:
        # LLM-detected issue: we don't have a rule definition, so we synthesise
        # the descriptor from the issue itself.
        name = rule_id
        short = sample_issue.description[:120]
        full = sample_issue.description
        help_text = sample_issue.recommendation
        default_level = SEVERITY_TO_LEVEL.get(sample_issue.severity.value, "warning")
        props = {
            "scanner": "llm",
            "ruleType": "ai-detected",
        }
        if sample_issue.compliance_ref:
            props["complianceRef"] = sample_issue.compliance_ref

    entry: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "help": {"text": help_text, "markdown": help_text},
        "defaultConfiguration": {"level": default_level},
    }
    if props:
        entry["properties"] = props
    return entry


def _build_result(issue: Issue, rule_id: str) -> dict[str, Any]:
    """Build a SARIF result (a single finding)."""
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": issue.file or "<unknown>"},
    }
    if issue.line is not None:
        region: dict[str, Any] = {"startLine": issue.line}
        if issue.code_snippet:
            region["snippet"] = {"text": issue.code_snippet[:500]}
        physical["region"] = region

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": SEVERITY_TO_LEVEL.get(issue.severity.value, "warning"),
        "message": {"text": issue.description},
        "locations": [{"physicalLocation": physical}],
    }

    # Attach compliance / category metadata as SARIF properties for tooling that reads them.
    result_props: dict[str, Any] = {
        "category": issue.category.value,
        "source": issue.source,
    }
    if issue.compliance_ref:
        result_props["complianceRef"] = issue.compliance_ref
    if issue.hipaa_reference:
        result_props["hipaaReference"] = issue.hipaa_reference
    result["properties"] = result_props
    return result


def build_sarif(report: ProjectReport) -> dict[str, Any]:
    """Convert a ProjectReport into a SARIF 2.1.0 document.

    Only rules referenced by at least one issue in this report are listed in
    the tool.driver.rules array. LLM-detected issues get synthetic IDs
    ('llm-0000', 'llm-0001', ...).
    """
    from app.services import rules_store  # local import: avoid circular

    rules_by_id = {r.id: r for r in rules_store.get_all_rules()}

    rule_entries: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    llm_counter = 0

    for issue in _all_issues(report):
        rule_id = issue.rule_id
        if not rule_id:
            rule_id = f"llm-{llm_counter:04d}"
            llm_counter += 1

        if rule_id not in rule_entries:
            rule_entries[rule_id] = _build_rule_entry(
                rule_id, issue, rules_by_id.get(rule_id) if issue.rule_id else None,
            )

        results.append(_build_result(issue, rule_id))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": CLARIX_NAME,
                        "version": CLARIX_VERSION,
                        "informationUri": CLARIX_INFO_URI,
                        "rules": list(rule_entries.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "repoName": report.repo_name,
                            "sourceType": report.source_type,
                            "analysisMode": (report.metadata or {}).get("analysis_mode", "unknown"),
                            "filesAnalyzed": (report.metadata or {}).get("total_files_analyzed", 0),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
