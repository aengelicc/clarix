"""Tests for the SARIF 2.1.0 export."""
import json

import pytest

from app.core.models import (
    Category,
    FileAnalysis,
    Issue,
    ProjectReport,
    Severity,
)
from app.services.sarif import (
    CLARIX_NAME,
    CLARIX_VERSION,
    SARIF_VERSION,
    build_sarif,
)


def _issue(rule_id=None, severity=Severity.HIGH, file_="src/app.py", line=10,
           description="test finding", recommendation="fix it", compliance_ref=None,
           source="hipaa_scanner"):
    return Issue(
        category=Category.SECURITY,
        severity=severity,
        file=file_,
        line=line,
        description=description,
        recommendation=recommendation,
        code_snippet=f"line {line} of {file_}",
        source=source,
        rule_id=rule_id,
        compliance_ref=compliance_ref,
    )


def test_sarif_top_level_shape():
    report = ProjectReport(repo_name="x", source_type="local")
    sarif = build_sarif(report)
    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"].startswith("https://json.schemastore.org/sarif-2.1.0")
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == CLARIX_NAME
    assert driver["version"] == CLARIX_VERSION
    assert driver["informationUri"].startswith("https://")


def test_sarif_empty_report_has_no_results_and_no_rules():
    report = ProjectReport(repo_name="x", source_type="local")
    sarif = build_sarif(report)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_static_rule_finding_uses_rule_id_and_lookup():
    """A rule_id from rules.json (e.g. 'hipaa-003') should appear as the SARIF ruleId."""
    report = ProjectReport(repo_name="x", source_type="local")
    report.security_findings.append(_issue(
        rule_id="hipaa-003", severity=Severity.HIGH,
        description="Potential SQL Injection — §164.312(a)(1) — Access Control.",
        compliance_ref="§164.312(a)(1) — Access Control",
    ))
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "hipaa-003"
    assert results[0]["level"] == "error"  # HIGH -> error

    # Rule descriptor should be enriched from the rules.json SecurityRule lookup.
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "hipaa-003"
    assert rule["properties"]["scanner"] == "hipaa"
    assert rule["properties"]["complianceRef"] == "§164.312(a)(1) — Access Control"


def test_severity_maps_to_sarif_level():
    report = ProjectReport(repo_name="x", source_type="local")
    for sev, expected in [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "none"),
    ]:
        report.security_findings.append(_issue(
            rule_id="hipaa-001", severity=sev, description=f"sev={sev.value}",
        ))
    sarif = build_sarif(report)
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert levels == {"error", "warning", "note", "none"}


def test_llm_issue_gets_synthetic_id():
    """An issue with rule_id=None (LLM-detected) gets a stable synthetic id like 'llm-0000'."""
    report = ProjectReport(repo_name="x", source_type="local")
    report.security_findings.append(_issue(
        rule_id=None, severity=Severity.MEDIUM, source="llm",
        description="LLM-detected issue", recommendation="rework",
    ))
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    assert results[0]["ruleId"] == "llm-0000"

    # The synthesized rule descriptor should mark this as an LLM rule.
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["scanner"] == "llm"


def test_multiple_llm_issues_get_sequential_ids():
    report = ProjectReport(repo_name="x", source_type="local")
    for _ in range(3):
        report.security_findings.append(_issue(rule_id=None, source="llm"))
    sarif = build_sarif(report)
    rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
    assert rule_ids == ["llm-0000", "llm-0001", "llm-0002"]


def test_same_static_rule_used_twice_lists_rule_once():
    report = ProjectReport(repo_name="x", source_type="local")
    report.file_analyses.append(FileAnalysis(
        file_path="a.py", language="Python", size_bytes=0, analyzed=True,
        issues=[_issue(rule_id="hipaa-001", line=1), _issue(rule_id="hipaa-001", line=2)],
    ))
    sarif = build_sarif(report)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids.count("hipaa-001") == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_locations_include_file_and_line():
    report = ProjectReport(repo_name="x", source_type="local")
    report.security_findings.append(_issue(rule_id="hipaa-001", file_="src/api/users.py", line=42))
    sarif = build_sarif(report)
    result = sarif["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/api/users.py"
    assert loc["region"]["startLine"] == 42
    assert "text" in loc["region"]["snippet"]


def test_location_without_line_still_serializes():
    report = ProjectReport(repo_name="x", source_type="local")
    report.security_findings.append(_issue(rule_id="hipaa-001", line=None))
    sarif = build_sarif(report)
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in loc


def test_sarif_is_valid_json_and_deterministic():
    report = ProjectReport(repo_name="x", source_type="local", metadata={"analysis_mode": "static"})
    report.security_findings.append(_issue(rule_id="hipaa-001"))
    sarif = build_sarif(report)
    # Re-serialise to confirm it's real JSON.
    text = json.dumps(sarif)
    parsed = json.loads(text)
    assert parsed == sarif
    # Invocation includes our custom properties.
    inv = parsed["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["properties"]["analysisMode"] == "static"


def test_sarif_collects_issues_from_all_sources():
    report = ProjectReport(repo_name="x", source_type="local")
    report.security_findings.append(_issue(rule_id="hipaa-001", line=1))
    report.file_analyses.append(FileAnalysis(
        file_path="b.py", language="Python", size_bytes=0, analyzed=True,
        issues=[_issue(rule_id="hipaa-002", line=5)],
    ))
    report.project_level_issues.append(_issue(rule_id="hipaa-003", line=None))
    sarif = build_sarif(report)
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert rule_ids == {"hipaa-001", "hipaa-002", "hipaa-003"}
