"""HIPAA Security Rule compliance scanning and checklist generation."""
import re
from pathlib import Path
from typing import List, Dict, Any
from app.core.models import Issue, HipaaChecklistItem, Severity, Category, SEVERITY_ORDER

# (name, pattern, severity, hipaa_ref, recommendation)
# All patterns use single-quote raw strings to safely contain double-quote characters.
HIPAA_PATTERNS = [
    (
        "Unencrypted HTTP Endpoint",
        r'["\']http://(?!localhost|127\.0\.0\.1|::1)[^"\']{4,}["\']',
        Severity.HIGH,
        "§164.312(e)(1) — Transmission Security",
        "Replace http:// with https:// for all external endpoints. ePHI in transit must be encrypted.",
    ),
    (
        "TLS Verification Disabled",
        r"verify\s*=\s*False|ssl_verify\s*=\s*False|VERIFY_SSL\s*=\s*False|checkCertificate\s*=\s*false",
        Severity.HIGH,
        "§164.312(e)(1) — Transmission Security",
        "Never disable TLS certificate verification. Disabling it exposes ePHI to man-in-the-middle attacks.",
    ),
    (
        "Weak Randomness in Security Context",
        r"random\.(random|randint|choice|shuffle|sample)\s*\(",
        Severity.MEDIUM,
        "§164.312(d) — Person Authentication",
        "Use secrets.token_hex() or secrets.token_urlsafe() for session tokens and authentication values.",
    ),
    (
        "Potential SQL Injection",
        r'(?i)(cursor\.execute|\.execute)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?(%s|%d|\+\s*\w)',
        Severity.HIGH,
        "§164.312(a)(1) — Access Control",
        "Use parameterized queries. SQL injection on a patient database constitutes unauthorized ePHI access.",
    ),
    (
        "Potential PHI in Logs",
        r"(?i)(log|print|logger|logging)\s*[\.\(].*?(patient|ssn|date_of_birth|dob|diagnosis|mrn|medical_record|phi|pii|insurance_id)",
        Severity.MEDIUM,
        "§164.312(b) — Audit Controls",
        "Do not log raw patient data. Log event types and record IDs only; mask or omit PHI fields entirely.",
    ),
    (
        "Insecure Deserialization (Pickle)",
        r"pickle\.loads?\s*\(",
        Severity.HIGH,
        "§164.312(c)(1) — Integrity",
        "pickle.loads() on untrusted data enables arbitrary code execution, risking complete ePHI compromise.",
    ),
    (
        "Hardcoded Healthcare API Credential",
        r'(?i)(ehr_key|fhir_key|hl7_secret|epic_key|cerner_key|allscripts_key)\s*[:=]\s*["\'][^"\']{6,}["\']',
        Severity.CRITICAL,
        "§164.308(a)(1) — Security Management Process",
        "Healthcare integration credentials must be stored in environment variables or a secrets manager.",
    ),
    (
        "Hardcoded JWT / Auth Secret",
        r'(?i)(jwt_secret|secret_key|signing_key|jwt_key)\s*[:=]\s*["\'][^"\']{8,}["\']',
        Severity.CRITICAL,
        "§164.312(d) — Person Authentication",
        "JWT secrets loaded from source code allow authentication bypass. Use environment variables or a vault.",
    ),
    (
        "Debug Mode Enabled",
        r"DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True",
        Severity.MEDIUM,
        "§164.308(a)(1) — Security Management Process",
        "Disable debug mode before deployment. Stack traces and verbose errors may expose ePHI.",
    ),
    (
        "Database Connection Without Encryption Flag",
        r'(?i)(mysql|postgresql|postgres|mongodb)://[^:\s]+:[^@\s]+@(?!.*ssl)',
        Severity.MEDIUM,
        "§164.312(e)(1) — Transmission Security",
        "Add SSL/TLS parameters to database URLs (e.g., ?sslmode=require) to encrypt ePHI in transit.",
    ),
    (
        "Weak Password Hashing Algorithm",
        r'hashlib\.(md5|sha1)\s*\(',
        Severity.HIGH,
        "§164.312(d) — Person Authentication",
        "MD5 and SHA-1 are cryptographically broken for password storage. Use bcrypt, argon2, or scrypt via passlib.",
    ),
    (
        "CORS Wildcard Origin",
        r'(?i)allow_origins?\s*=.*\*|Access-Control-Allow-Origin.+\*',
        Severity.HIGH,
        "§164.312(a)(1) — Access Control",
        "A wildcard CORS origin allows any domain to call your API. Restrict to a known allow-list of trusted origins.",
    ),
    (
        "Insecure Session Cookie",
        r'(?i)(Secure\s*=\s*False|HttpOnly\s*=\s*False|httponly\s*=\s*False|secure\s*=\s*0)',
        Severity.MEDIUM,
        "§164.312(e)(1) — Transmission Security",
        "Session cookies must set Secure=True and HttpOnly=True to prevent ePHI session tokens from being stolen.",
    ),
    (
        "S3 Bucket Public-Read ACL",
        r'ACL\s*=\s*[\'"]public-(read|read-write)[\'"]',
        Severity.CRITICAL,
        "§164.312(a)(1) — Access Control",
        "Public S3 ACLs expose all stored objects to the internet. Use private ACLs with pre-signed URLs for authorized access to ePHI.",
    ),
    (
        "Hardcoded SSN in Source",
        r'\b\d{3}-\d{2}-\d{4}\b',
        Severity.HIGH,
        "§164.308(a)(1) — Security Management Process",
        "Social Security Numbers must not appear in source code or test fixtures. Use synthetic or de-identified test data.",
    ),
    (
        "Unparameterized NoSQL Query",
        r'(?i)(\.find|\.findOne|\.aggregate)\s*\(\s*\{[^}]*\+|(?:request\.|req\.)\w+.*\$(?:where|regex|expr)',
        Severity.HIGH,
        "§164.312(a)(1) — Access Control",
        "User-controlled input injected into NoSQL queries can bypass access controls on ePHI. Use schema validation and sanitization.",
    ),
    (
        "Plaintext ePHI Written to Disk",
        r'(?i)open\s*\([^)]*["\']w["\'][^)]*\).*(?:ssn|patient|diagnosis|mrn|phi|dob|date_of_birth)|(?:ssn|patient_id|diagnosis|mrn|phi)\s*=.*write\s*\(',
        Severity.HIGH,
        "§164.312(e)(2) — Encryption",
        "ePHI written to disk must be encrypted at rest. Use encrypted storage or apply AES-256 encryption before writing.",
    ),
]

HIPAA_CHECKLIST_TEMPLATE = [
    {
        "section": "§164.308(a)(1)",
        "title": "Administrative Safeguards — Security Management Process",
        "description": "Risk analysis, risk management, sanction policy, and information system activity review.",
        "ref_substring": "Security Management",
    },
    {
        "section": "§164.312(a)(1)",
        "title": "Technical Safeguards — Access Control",
        "description": "Unique user identification, emergency access, automatic logoff, encryption/decryption.",
        "ref_substring": "Access Control",
    },
    {
        "section": "§164.312(b)",
        "title": "Technical Safeguards — Audit Controls",
        "description": "Mechanisms to record and examine activity in systems that contain ePHI.",
        "ref_substring": "Audit Controls",
    },
    {
        "section": "§164.312(c)(1)",
        "title": "Technical Safeguards — Integrity",
        "description": "Policies and procedures to protect ePHI from improper alteration or destruction.",
        "ref_substring": "Integrity",
    },
    {
        "section": "§164.312(d)",
        "title": "Technical Safeguards — Person Authentication",
        "description": "Verify the identity of persons seeking access to ePHI.",
        "ref_substring": "Person Authentication",
    },
    {
        "section": "§164.312(e)(1)",
        "title": "Technical Safeguards — Transmission Security",
        "description": "Guard against unauthorized access to ePHI transmitted over electronic networks.",
        "ref_substring": "Transmission Security",
    },
    {
        "section": "§164.312(e)(2)",
        "title": "Technical Safeguards — Encryption at Rest",
        "description": "Implement a mechanism to encrypt and decrypt ePHI stored on systems and portable media.",
        "ref_substring": "Encryption",
    },
]



def scan_hipaa(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    """Scan a file for HIPAA Security Rule violations, returning tagged Issues."""
    from app.services import rules_store
    issues = []
    lines = content.splitlines()
    for rule in rules_store.get_active_rules(scanner="hipaa"):
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
                    hipaa_reference=rule.compliance_ref,
                    compliance_ref=rule.compliance_ref,
                    code_snippet=stripped[:150],
                    source="hipaa_scanner",
                ))
    return issues


def build_hipaa_checklist(all_issues: List[Issue]) -> List[HipaaChecklistItem]:
    """Map HIPAA-tagged findings to regulatory sections, returning a compliance checklist."""
    checklist = []
    for item in HIPAA_CHECKLIST_TEMPLATE:
        relevant = [
            i for i in all_issues
            if i.hipaa_reference and item["ref_substring"] in i.hipaa_reference
        ]
        worst_idx = max(
            (SEVERITY_ORDER.index(i.severity.value) for i in relevant),
            default=-1,
        )
        checklist.append(HipaaChecklistItem(
            section=item["section"],
            title=item["title"],
            description=item["description"],
            findings_count=len(relevant),
            status="fail" if relevant else "pass",
            worst_severity=SEVERITY_ORDER[worst_idx] if worst_idx >= 0 else None,
        ))
    return checklist
