"""PCI-DSS v4.0 compliance scanning."""
import re
from pathlib import Path
from typing import List
from app.core.models import Issue, ComplianceChecklistItem, Severity, Category, SEVERITY_ORDER

# (name, pattern, severity, pci_ref, recommendation)
PCI_PATTERNS = [
    (
        "Cardholder PAN in Source Code",
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        Severity.CRITICAL,
        "PCI-DSS Req 3.4 — Stored Cardholder Data",
        "Primary Account Numbers must never appear in source code. Use tokenization or masked test surrogates.",
    ),
    (
        "CVV/CVC Storage",
        r'(?i)(cvv2?|cvc2?|card_verification|card_security_code)\s*[:=]\s*["\'][0-9]{3,4}["\']',
        Severity.CRITICAL,
        "PCI-DSS Req 3.3 — Prohibited Data",
        "CVV/CVC codes must never be stored after authorization. Storage is prohibited regardless of encryption.",
    ),
    (
        "Magnetic Stripe Track Data",
        r'(?i)(track_?[12]|trackdata|magstripe|magnetic_stripe)\s*[:=]',
        Severity.CRITICAL,
        "PCI-DSS Req 3.3 — Prohibited Data",
        "Magnetic stripe track data must never be stored after authorization. Remove storage and retention code entirely.",
    ),
    (
        "Unencrypted Payment Endpoint",
        r'(?i)["\']http://[^"\']*(?:payment|checkout|card|billing|stripe|paypal|braintree)[^"\']*["\']',
        Severity.CRITICAL,
        "PCI-DSS Req 4.2 — Transmission Security",
        "All cardholder data transmission must use TLS 1.2+. Replace http:// with https:// on all payment endpoints.",
    ),
    (
        "Prohibited Weak Cipher",
        r'(?i)\b(DES|3DES|Triple.?DES|RC4|RC2)\b',
        Severity.HIGH,
        "PCI-DSS Req 4.2 — Transmission Security",
        "DES, 3DES, and RC4 are prohibited for protecting cardholder data. Use AES-256 with GCM or CBC+HMAC.",
    ),
    (
        "Hardcoded Payment Processor Credential",
        r'(?i)(stripe_secret|stripe_key|paypal_secret|paypal_key|braintree_key|merchant_key|acquirer_key|payment_api_key|square_key|adyen_key)\s*[:=]\s*["\'][^"\']{8,}["\']',
        Severity.CRITICAL,
        "PCI-DSS Req 6.3 — Security Vulnerabilities",
        "Payment processor credentials must be stored in environment variables or a secrets manager, never in source code.",
    ),
    (
        "Card Data in Application Logs",
        r'(?i)(log|print|logger|logging)\s*[\.\(].*(?:card_?number|pan|account_?number|credit_?card)',
        Severity.HIGH,
        "PCI-DSS Req 10.2 — Audit Logging",
        "PAN and card data must never appear in logs. Log only masked values (last 4 digits) for audit purposes.",
    ),
    (
        "Default or Weak Credential",
        r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'](?:password|Password|admin|123456|test|default|secret|changeme|12345|qwerty)["\']',
        Severity.HIGH,
        "PCI-DSS Req 8.3 — Authentication Management",
        "Default credentials fail PCI-DSS Req 8. Deploy with unique strong credentials and rotate on a defined schedule.",
    ),
    (
        "Plaintext Card Data Written to File",
        r'(?i)open\s*\([^)]*["\']w["\'][^)]*\).*(?:card|pan|account_number|credit)|(?:card|pan|account_number)\s*=.*write\s*\(',
        Severity.CRITICAL,
        "PCI-DSS Req 3.5 — Encryption of Stored Data",
        "Stored cardholder data must be encrypted with AES-256. Never write PAN or card data to plaintext files.",
    ),
    (
        "Missing PCI Scope Isolation",
        r'(?i)(card|cardholder|pan|payment)\s*=.*(?:os\.environ|getenv|config\[)',
        Severity.LOW,
        "PCI-DSS Req 12.5 — Scope Management",
        "Ensure cardholder data environment (CDE) systems are isolated from out-of-scope systems. Review network segmentation.",
    ),
]

PCI_CHECKLIST_TEMPLATE = [
    {
        "section": "Req 3",
        "title": "Protect Stored Cardholder Data",
        "description": "Do not store prohibited data (CVV, track data). Encrypt stored PANs with strong cryptography.",
        "ref_substring": "Stored Cardholder Data",
    },
    {
        "section": "Req 3.3",
        "title": "Prohibited Data Storage",
        "description": "CVV/CVC codes and full magnetic stripe track data must never be stored after authorization.",
        "ref_substring": "Prohibited Data",
    },
    {
        "section": "Req 4",
        "title": "Encrypt Cardholder Data in Transit",
        "description": "Use strong cryptography (TLS 1.2+) to safeguard cardholder data during transmission over open networks.",
        "ref_substring": "Transmission Security",
    },
    {
        "section": "Req 6",
        "title": "Develop and Maintain Secure Systems",
        "description": "Protect all system components from known vulnerabilities. Apply security patches; avoid hardcoded credentials.",
        "ref_substring": "Security Vulnerabilities",
    },
    {
        "section": "Req 8",
        "title": "Identify and Authenticate Access",
        "description": "Assign unique IDs, enforce strong authentication, and prohibit default or shared credentials.",
        "ref_substring": "Authentication Management",
    },
    {
        "section": "Req 10",
        "title": "Log and Monitor All Access",
        "description": "Implement audit logging for all access to cardholder data and critical system components.",
        "ref_substring": "Audit Logging",
    },
]



def scan_pci(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    """Scan a file for PCI-DSS v4.0 compliance violations."""
    from app.services import rules_store
    issues = []
    lines = content.splitlines()
    for rule in rules_store.get_active_rules(scanner="pci"):
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
                    source="pci_scanner",
                    rule_id=rule.id,
                ))
    return issues


def build_pci_checklist(all_issues: List[Issue]) -> List[ComplianceChecklistItem]:
    """Map PCI-tagged findings to requirement sections."""
    checklist = []
    for item in PCI_CHECKLIST_TEMPLATE:
        relevant = [
            i for i in all_issues
            if i.compliance_ref and item["ref_substring"] in i.compliance_ref
        ]
        worst_idx = max(
            (SEVERITY_ORDER.index(i.severity.value) for i in relevant),
            default=-1,
        )
        checklist.append(ComplianceChecklistItem(
            framework="PCI-DSS",
            section=item["section"],
            title=item["title"],
            description=item["description"],
            findings_count=len(relevant),
            status="fail" if relevant else "pass",
            worst_severity=SEVERITY_ORDER[worst_idx] if worst_idx >= 0 else None,
        ))
    return checklist
