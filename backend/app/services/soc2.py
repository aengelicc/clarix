"""SOC 2 Trust Service Criteria compliance scanning."""
import re
from pathlib import Path
from typing import List
from app.core.models import Issue, ComplianceChecklistItem, Severity, Category

SOC2_PATTERNS = [
    (
        "Authentication Bypass Flag",
        r'(?i)(skip_auth|bypass_auth|auth_disabled|disable_auth|no_auth)\s*=\s*True',
        Severity.CRITICAL,
        "SOC 2 CC6.1 — Logical Access Controls",
        "Authentication bypass flags must never be deployed. Remove entirely; use environment-gated feature flags.",
    ),
    (
        "Debug Backdoor or Maintenance Mode",
        r'(?i)(backdoor|debug_bypass|dev_only|admin_backdoor|maintenance_mode)\s*=\s*True',
        Severity.CRITICAL,
        "SOC 2 CC6.1 — Logical Access Controls",
        "Backdoor and maintenance-mode access paths violate SOC 2 logical access controls. Remove from production code entirely.",
    ),
    (
        "CORS Wildcard Origin",
        r'(?i)allow_origins?\s*=.*\*|Access-Control-Allow-Origin.+\*',
        Severity.HIGH,
        "SOC 2 CC6.6 — External Threats",
        "Wildcard CORS grants unrestricted cross-origin access. Restrict to an explicit allow-list of known trusted origins.",
    ),
    (
        "Insecure Direct Object Reference",
        r'(?i)(?:\.get|\.find|\.filter|WHERE)\s*\(?.*(?:id|user_id|record_id)\s*=\s*(?:request|req)\.\w+',
        Severity.HIGH,
        "SOC 2 CC6.1 — Logical Access Controls",
        "Direct use of user-supplied IDs in queries risks unauthorized data access. Verify record ownership before returning data.",
    ),
    (
        "Silent Exception Swallowing",
        r'except\s*(?:Exception\s*)?\s*:\s*\n\s*pass\b|catch\s*\([^)]*\)\s*\{\s*\}',
        Severity.MEDIUM,
        "SOC 2 CC7.2 — System Monitoring",
        "Silent exception handling hides operational failures. Log all exceptions with context and alert on unexpected error rates.",
    ),
    (
        "Privileged Operation Without Audit Log",
        r'(?i)def\s+(delete_\w+|drop_\w+|purge_\w+|admin_\w+|revoke_\w+)\s*\([^)]*\):\n(?!\s*(?:log|audit|logger))',
        Severity.MEDIUM,
        "SOC 2 CC7.3 — Audit Logging",
        "Destructive and privileged operations must produce audit log entries. Log actor, action, timestamp, and affected resource ID.",
    ),
    (
        "Unrestricted File Upload",
        r'(?i)(file\.save|\.put_object|store_file|upload_file)\s*\([^)]*\)(?![^\n]*(?:check|valid|allow|extension|content.type))',
        Severity.HIGH,
        "SOC 2 CC6.8 — Input Validation",
        "Unrestricted file uploads enable code execution and storage abuse. Validate type, size, and content before persisting.",
    ),
    (
        "HTTPS Not Enforced",
        r'(?i)SECURE_SSL_REDIRECT\s*=\s*False|force_https\s*=\s*False|require_https\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False',
        Severity.HIGH,
        "SOC 2 CC6.7 — Transmission Controls",
        "HTTPS must be enforced for all production traffic. Enable SECURE_SSL_REDIRECT and SESSION_COOKIE_SECURE before deployment.",
    ),
    (
        "Hardcoded Inter-Service Token",
        r'(?i)(service_token|internal_key|inter_service|service_secret|internal_secret|svc_key)\s*[:=]\s*["\'][^"\']{8,}["\']',
        Severity.CRITICAL,
        "SOC 2 CC6.3 — Access Provisioning",
        "Inter-service credentials hardcoded in source enable lateral movement. Use a secrets manager or mTLS for service-to-service auth.",
    ),
    (
        "Test Credentials Left in Code",
        r'(?i)(test_key|test_token|test_secret|test_password|dev_key|dummy_key|fake_token)\s*[:=]\s*["\'][^"\']{6,}["\']',
        Severity.HIGH,
        "SOC 2 CC6.3 — Access Provisioning",
        "Test credentials in production code violate environment separation. Remove or gate behind strict environment checks.",
    ),
]

SOC2_CHECKLIST_TEMPLATE = [
    {
        "section": "CC6.1",
        "title": "Logical and Physical Access Controls",
        "description": "Restrict logical access to authorized users; implement authentication, authorization, and access revocation.",
        "ref_substring": "CC6.1",
    },
    {
        "section": "CC6.3",
        "title": "Access Provisioning and Deprovisioning",
        "description": "Manage credentials and access rights through a formal provisioning process; remove or rotate when no longer needed.",
        "ref_substring": "CC6.3",
    },
    {
        "section": "CC6.6",
        "title": "External Threats",
        "description": "Implement controls to prevent unauthorized access from external sources including network segmentation and CORS policy.",
        "ref_substring": "CC6.6",
    },
    {
        "section": "CC6.7",
        "title": "Transmission Controls",
        "description": "Protect data in transit using encryption (TLS 1.2+) and enforce HTTPS for all production endpoints.",
        "ref_substring": "CC6.7",
    },
    {
        "section": "CC6.8",
        "title": "Input Validation and Processing Integrity",
        "description": "Validate and sanitize all external inputs to prevent injection attacks and unauthorized data processing.",
        "ref_substring": "CC6.8",
    },
    {
        "section": "CC7.2",
        "title": "System Monitoring",
        "description": "Monitor system components for anomalies, alert on security events, and maintain operational visibility.",
        "ref_substring": "CC7.2",
    },
    {
        "section": "CC7.3",
        "title": "Audit Logging",
        "description": "Record and retain audit logs for all privileged, security-relevant, and data-modifying operations.",
        "ref_substring": "CC7.3",
    },
]

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def scan_soc2(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    """Scan a file for SOC 2 Trust Service Criteria violations."""
    from app.services import rules_store
    issues = []
    lines = content.splitlines()
    for rule in rules_store.get_active_rules(scanner="soc2"):
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue
            if re.search(rule.pattern, line):
                issues.append(Issue(
                    category=Category.SECURITY,
                    severity=rule.severity,
                    file=relative_path,
                    line=i,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    compliance_ref=rule.compliance_ref,
                    code_snippet=stripped[:150],
                    source="soc2_scanner",
                ))
    return issues


def build_soc2_checklist(all_issues: List[Issue]) -> List[ComplianceChecklistItem]:
    """Map SOC 2-tagged findings to Trust Service Criteria sections."""
    checklist = []
    for item in SOC2_CHECKLIST_TEMPLATE:
        relevant = [
            i for i in all_issues
            if i.compliance_ref and item["ref_substring"] in i.compliance_ref
        ]
        worst_idx = max(
            (_SEV_ORDER.index(i.severity.value) for i in relevant),
            default=-1,
        )
        checklist.append(ComplianceChecklistItem(
            framework="SOC 2",
            section=item["section"],
            title=item["title"],
            description=item["description"],
            findings_count=len(relevant),
            status="fail" if relevant else "pass",
            worst_severity=_SEV_ORDER[worst_idx] if worst_idx >= 0 else None,
        ))
    return checklist
