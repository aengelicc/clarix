"""GDPR compliance scanning."""
import re
from pathlib import Path
from typing import List
from app.core.models import Issue, ComplianceChecklistItem, Severity, Category, SEVERITY_ORDER

GDPR_PATTERNS = [
    (
        "Personal Data in Application Logs",
        r'(?i)(log|print|logger|logging)\s*[\.\(].*(?:email|phone|address|birth|national_id|passport|ip_addr|customer_id|user_name)',
        Severity.MEDIUM,
        "GDPR Art. 5(1)(f) — Integrity and Confidentiality",
        "Personal data must not appear in logs. Log event IDs only; redact or pseudonymize PII in all log outputs.",
    ),
    (
        "Third-Party Tracker Without Consent",
        r'(?i)(google-analytics\.com|googletagmanager\.com|facebook\.net/en_US/fbevents|hotjar\.com|mixpanel\.com|segment\.com|amplitude\.com)',
        Severity.HIGH,
        "GDPR Art. 7 — Conditions for Consent",
        "Third-party analytics and tracking require explicit prior consent under GDPR. Implement a Consent Management Platform.",
    ),
    (
        "Personal Data Written to File Unencrypted",
        r'(?i)(?:json\.dump|pickle\.dump|csv\.write|open.*["\']w["\'])\s*\(.*(?:email|phone|name|address|birth|national_id|passport)',
        Severity.HIGH,
        "GDPR Art. 32 — Security of Processing",
        "Personal data written to files must be encrypted at rest with AES-256. Verify access controls on the file path.",
    ),
    (
        "IP Address Stored Without Masking",
        r'(?i)(ip_address|client_ip|remote_addr|x_forwarded_for)\s*=\s*(?:request|req)\.\w+',
        Severity.MEDIUM,
        "GDPR Art. 5(1)(c) — Data Minimisation",
        "IP addresses are personal data under GDPR. Anonymize the last octet before storage or document the Art. 6 legal basis.",
    ),
    (
        "Personal Data in Error Messages",
        r'(?i)(?:raise|throw)\s*\w*\([^)]*(?:email|user|customer|phone|address)',
        Severity.MEDIUM,
        "GDPR Art. 5(1)(f) — Integrity and Confidentiality",
        "Error messages must not expose personal data. Log full detail server-side only; show a generic message to end users.",
    ),
    (
        "Sensitive PII Field Without Encryption Indicator",
        r'(?i)(ssn|social_security|national_id|passport_number|date_of_birth|credit_card|iban|tax_id)\s*=\s*(?!.*encrypt)',
        Severity.HIGH,
        "GDPR Art. 32 — Security of Processing",
        "Sensitive personal identifiers must be encrypted or pseudonymized at rest. Use column-level encryption for sensitive fields.",
    ),
    (
        "Cookie Set Without Consent Check",
        r'(?i)document\.cookie\s*=|res\.cookie\s*\(|response\.set_cookie\s*\(',
        Severity.MEDIUM,
        "GDPR Art. 7 — Conditions for Consent",
        "Non-essential cookies require explicit user consent before setting. Integrate a Consent Management Platform.",
    ),
    (
        "Personal Data Hashed With Weak Algorithm",
        r'(?i)hashlib\.(md5|sha1)\s*\([^)]*(?:email|name|ssn|user|id)',
        Severity.HIGH,
        "GDPR Art. 32 — Security of Processing",
        "MD5/SHA-1 pseudonymization is reversible via rainbow tables. Use SHA-256 with salt, or bcrypt/argon2 for identity fields.",
    ),
    (
        "Data Transfer to Non-EEA Cloud Service",
        r'(?i)["\']https?://[^"\']*(?:s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^"\']*["\']',
        Severity.LOW,
        "GDPR Art. 44 — Transfer to Third Countries",
        "Transferring personal data to non-EEA processors requires SCCs or an adequacy decision. Verify data residency configuration.",
    ),
    (
        "Missing Data Deletion / Expiry Field",
        r'(?i)CREATE\s+TABLE\s+\w*(?:user|customer|member|subscriber)\w*\s*\([^;]*\)(?![^;]*(?:deleted_at|expires_at|expiry|ttl))',
        Severity.LOW,
        "GDPR Art. 5(1)(e) — Storage Limitation",
        "Personal data must not be retained longer than necessary. Add a deleted_at or expires_at field and enforce deletion schedules.",
    ),
]

GDPR_CHECKLIST_TEMPLATE = [
    {
        "section": "Art. 5",
        "title": "Principles of Processing",
        "description": "Personal data must be processed lawfully, minimized, accurate, time-limited, secure, and with accountability.",
        "ref_substring": "Art. 5",
    },
    {
        "section": "Art. 7",
        "title": "Conditions for Consent",
        "description": "Consent must be freely given, specific, informed, and unambiguous. Pre-ticked boxes and bundled consent are invalid.",
        "ref_substring": "Art. 7",
    },
    {
        "section": "Art. 32",
        "title": "Security of Processing",
        "description": "Implement pseudonymization, encryption, resilience, and regular security testing appropriate to the risk.",
        "ref_substring": "Art. 32",
    },
    {
        "section": "Art. 44",
        "title": "International Data Transfers",
        "description": "Personal data transfers outside the EEA require adequate safeguards: SCCs, BCRs, or adequacy decisions.",
        "ref_substring": "Art. 44",
    },
    {
        "section": "Art. 5(1)(e)",
        "title": "Storage Limitation",
        "description": "Personal data must be kept no longer than necessary and deleted or anonymized when the purpose expires.",
        "ref_substring": "Storage Limitation",
    },
]

def scan_gdpr(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    """Scan a file for GDPR compliance violations."""
    from app.services import rules_store
    issues = []
    lines = content.splitlines()
    for rule in rules_store.get_active_rules(scanner="gdpr"):
        if "\\n" in rule.pattern or "\n" in rule.pattern:
            # Multi-line pattern: match against the full file content.
            m = re.search(rule.pattern, content, re.MULTILINE | re.DOTALL)
            if m:
                line_num = content[: m.start()].count("\n") + 1
                issues.append(Issue(
                    category=Category.SECURITY,
                    severity=rule.severity,
                    file=relative_path,
                    line=line_num,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    compliance_ref=rule.compliance_ref,
                    source="gdpr_scanner",
                    rule_id=rule.id,
                ))
        else:
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
                        source="gdpr_scanner",
                        rule_id=rule.id,
                    ))
    return issues


def build_gdpr_checklist(all_issues: List[Issue]) -> List[ComplianceChecklistItem]:
    """Map GDPR-tagged findings to article sections."""
    checklist = []
    for item in GDPR_CHECKLIST_TEMPLATE:
        relevant = [
            i for i in all_issues
            if i.compliance_ref and item["ref_substring"] in i.compliance_ref
        ]
        worst_idx = max(
            (SEVERITY_ORDER.index(i.severity.value) for i in relevant),
            default=-1,
        )
        checklist.append(ComplianceChecklistItem(
            framework="GDPR",
            section=item["section"],
            title=item["title"],
            description=item["description"],
            findings_count=len(relevant),
            status="fail" if relevant else "pass",
            worst_severity=SEVERITY_ORDER[worst_idx] if worst_idx >= 0 else None,
        ))
    return checklist
