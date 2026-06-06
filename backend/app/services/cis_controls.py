"""CIS Critical Security Controls v8 compliance scanning.

Covers the code-scannable subset of CIS Controls v8. Implementation Group
(IG) levels are noted in each rule's compliance_ref so the CIS view surfaces
priorities (IG1 = basic cyber hygiene, IG2 = intermediate, IG3 = advanced).
"""
import re
from pathlib import Path
from typing import List

from app.core.models import Issue, ComplianceChecklistItem, Severity, Category, SEVERITY_ORDER


# (name, pattern, severity, cis_ref, recommendation)
CIS_PATTERNS = [
    # --- Control 3: Data Protection ---------------------------------------
    (
        "Personal Data Written Unencrypted to Disk",
        r'(?i)(?:json\.dump|pickle\.dump|csv\.writer|open\s*\(\s*[^)]*["\']w["\'])\s*\([^)]*(?:ssn|patient|email|phone|address|date_of_birth|dob|mrn|pan|card_number)',
        Severity.HIGH,
        "CIS v8 3.11 (IG1)",
        "Sensitive data written to files must be encrypted at rest. Use AES-256 (or column-level encryption) before persisting.",
    ),
    (
        "Sensitive Field Stored in Plaintext Variable",
        r'(?i)(ssn|social_security|national_id|passport_number|date_of_birth|credit_card|iban|tax_id)\s*=\s*(?!.*encrypt)',
        Severity.HIGH,
        "CIS v8 3.11 (IG1)",
        "Sensitive identifiers must be encrypted or pseudonymised at rest. Mask or hash before storing in memory beyond a single request scope.",
    ),

    # --- Control 4: Secure Configuration ----------------------------------
    (
        "Debug Mode Enabled in Configuration",
        r'DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True',
        Severity.MEDIUM,
        "CIS v8 4.1 (IG1)",
        "Disable debug mode before deployment. Stack traces and debug consoles expose internals and may allow code execution.",
    ),
    (
        "Default or Vendor Credential",
        r'(?i)(?:password|passwd|pwd|api_key|secret)\s*[:=]\s*["\'](?:password|Password|admin|123456|test|default|secret|changeme|12345|qwerty|root)["\']',
        Severity.HIGH,
        "CIS v8 4.2 (IG1)",
        "Default/vendor credentials must be replaced before deployment. Rotate on a defined schedule.",
    ),
    (
        "TLS Verification Disabled",
        r'verify\s*=\s*False|ssl_verify\s*=\s*False|VERIFY_SSL\s*=\s*False|checkCertificate\s*=\s*false',
        Severity.HIGH,
        "CIS v8 4.6 (IG1)",
        "Never disable TLS certificate verification. Disabling it exposes transport data to man-in-the-middle attacks.",
    ),
    (
        "Unencrypted HTTP Endpoint (external)",
        r'["\']http://(?!localhost|127\.0\.0\.1|::1)[^"\']{4,}["\']',
        Severity.HIGH,
        "CIS v8 4.6 (IG1)",
        "Replace http:// with https:// for all external endpoints. Plaintext transport exposes data in transit.",
    ),

    # --- Control 5: Account Management ------------------------------------
    (
        "Hardcoded User Credential",
        r'(?i)(?:username|user|email)\s*[:=]\s*["\'][^"\']{3,}["\'].*(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
        Severity.CRITICAL,
        "CIS v8 5.2 (IG1)",
        "User credentials must not appear in source. Use environment variables or a secrets manager; rotate any committed value.",
    ),
    (
        "Generic Account Name (admin/root) Hardcoded",
        r'(?i)[\'\"](?:admin|administrator|root|superuser)[\'"]\s*[:=]\s*[\'"][^"\']+[\'"]',
        Severity.MEDIUM,
        "CIS v8 5.4 (IG1)",
        "Hardcoded admin/root accounts in source defeat least-privilege. Use a real user store with role-based provisioning.",
    ),

    # --- Control 6: Access Control Management -----------------------------
    (
        "Authentication Bypass Flag",
        r'(?i)(?:skip_auth|bypass_auth|auth_disabled|disable_auth|no_auth)\s*=\s*True',
        Severity.CRITICAL,
        "CIS v8 6.8 (IG2)",
        "Authentication bypass flags must never be deployed. Remove entirely; use environment-gated feature flags if you need a non-prod override.",
    ),
    (
        "Debug Backdoor / Maintenance Mode",
        r'(?i)(?:backdoor|debug_bypass|dev_only|admin_backdoor|maintenance_mode)\s*=\s*True',
        Severity.CRITICAL,
        "CIS v8 6.8 (IG2)",
        "Backdoor and maintenance-mode access paths violate least-privilege. Remove from production code entirely.",
    ),
    (
        "Insecure Direct Object Reference",
        r'(?i)(?:\.get|\.find|\.filter|WHERE)\s*\(?.*(?:id|user_id|record_id|order_id)\s*=\s*(?:request|req)\.\w+',
        Severity.HIGH,
        "CIS v8 6.7 (IG2)",
        "Direct use of user-supplied IDs in queries risks unauthorized data access. Verify record ownership before returning data.",
    ),
    (
        "CORS Wildcard Origin",
        r'(?i)allow_origins?\s*=.*\*|Access-Control-Allow-Origin.+\*',
        Severity.HIGH,
        "CIS v8 6.7 (IG2)",
        "Wildcard CORS grants unrestricted cross-origin access. Restrict to an explicit allow-list of known trusted origins.",
    ),

    # --- Control 8: Audit Log Management ----------------------------------
    (
        "Silent Exception Swallowing",
        r'except\s*(?:Exception\s*)?\s*:\s*\n\s*pass\b|catch\s*\([^)]*\)\s*\{\s*\}',
        Severity.MEDIUM,
        "CIS v8 8.2 (IG2)",
        "Silent exception handling hides operational failures. Log the exception with context; alert on unexpected error rates.",
    ),
    (
        "Privileged Operation Without Audit Log",
        r'(?i)def\s+(?:delete_\w+|drop_\w+|purge_\w+|admin_\w+|revoke_\w+|destroy_\w+)\s*\([^)]*\):\s*\n(?!\s*(?:log|audit|logger|logging|print))',
        Severity.MEDIUM,
        "CIS v8 8.5 (IG2)",
        "Destructive and privileged operations must produce audit log entries. Log actor, action, timestamp, and affected resource ID.",
    ),
    (
        "Print/Console Logging on Production Path",
        r'(?i)^\s*(?:print|console\.log|System\.out\.println)\s*\(',
        Severity.LOW,
        "CIS v8 8.2 (IG2)",
        "Production code should use a structured logger, not print/console. Ensure sensitive values are not passed to the logger.",
    ),

    # --- Control 16: Application Software Security -----------------------
    (
        "SQL Injection — String Concatenation",
        r'(?i)(?:cursor\.execute|\.execute|\.raw)\s*\(\s*["\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?(%s|%d|\+\s*\w)',
        Severity.CRITICAL,
        "CIS v8 16.10 (IG2)",
        "String-formatted SQL queries are injection-prone. Use parameterised queries or an ORM's bound parameters.",
    ),
    (
        "Command Injection — User Input Concatenated into exec",
        r'(?i)(?:os\.popen|subprocess\.(?:call|run|Popen)|child_process\.exec|execSync)\s*\(\s*[^)]*(?:\+|`|\$\(|\$\{)',
        Severity.CRITICAL,
        "CIS v8 16.10 (IG2)",
        "Concatenating user input into a shell command enables command injection. Use argv arrays and validate/escape inputs, or call the binary directly.",
    ),
    (
        "Insecure Deserialization (Pickle / Marshal / Java ObjectInputStream)",
        r'pickle\.loads?\s*\(|marshal\.loads?\s*\(|ObjectInputStream.*readObject',
        Severity.CRITICAL,
        "CIS v8 16.10 (IG2)",
        "Deserialising untrusted data enables remote code execution. Use json or a typed serializer; never unpickle attacker-controlled bytes.",
    ),
    (
        "Path Traversal — User Input in File Path",
        r'(?i)(?:open|send_file|send_from_directory|File\s*\(\s*[^)]*?,\s*["\'][wa]["\'])\s*\(\s*[^)]*(?:\+|\.format|f["\'])',
        Severity.HIGH,
        "CIS v8 16.10 (IG2)",
        "Concatenating user input into a file path enables path traversal. Resolve to an absolute, normalised path and verify it stays within an allow-listed root.",
    ),
    (
        "Weak Hash (MD5/SHA-1)",
        r'hashlib\.(md5|sha1)\s*\(',
        Severity.HIGH,
        "CIS v8 16.11 (IG2)",
        "MD5 and SHA-1 are cryptographically broken. Use SHA-256+ for integrity and bcrypt/argon2/scrypt for password storage.",
    ),
    (
        "Prohibited Weak Cipher",
        r'(?i)\b(DES|3DES|Triple.?DES|RC4|RC2|MD4)\b',
        Severity.HIGH,
        "CIS v8 16.11 (IG2)",
        "DES, 3DES, RC4, RC2, and MD4 are broken or deprecated. Use AES-256-GCM or ChaCha20-Poly1305.",
    ),
    (
        "innerHTML / document.write (XSS sink)",
        r'innerHTML\s*[=+:]|outerHTML\s*[=+:]|document\.write\s*\(',
        Severity.MEDIUM,
        "CIS v8 16.10 (IG2)",
        "Direct DOM assignment of unescaped data is an XSS sink. Set .textContent / use a framework's safe binding, or sanitise via DOMPurify.",
    ),
    (
        "SSRF — User Input in HTTP Client URL",
        r'(?i)(?:requests?\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|httpx\.(?:get|post|client)|axios\.(?:get|post)|fetch\s*\()\s*\([^)]*(?:request|req)\.\w+',
        Severity.HIGH,
        "CIS v8 16.10 (IG2)",
        "Passing request data directly to an HTTP client enables SSRF. Validate the URL against an allow-list of permitted hosts/schemes.",
    ),
    (
        "Open Redirect — User Input in redirect()",
        r'(?i)(?:redirect|HttpResponseRedirect)\s*\(\s*(?:request|req)\.\w+',
        Severity.MEDIUM,
        "CIS v8 16.10 (IG2)",
        "Redirecting to a user-supplied URL enables phishing chains. Validate the target against an allow-list or use indirect references.",
    ),
    (
        "Hardcoded Inter-Service / API Token",
        r'(?i)(?:service_token|internal_key|inter_service|service_secret|internal_secret|svc_key|api_token|auth_token)\s*[:=]\s*["\'][^"\']{8,}["\']',
        Severity.CRITICAL,
        "CIS v8 16.14 (IG2)",
        "Inter-service credentials hardcoded in source enable lateral movement. Use a secrets manager or mTLS for service-to-service auth.",
    ),
]


CIS_CHECKLIST_TEMPLATE = [
    {
        "section": "3.11",
        "title": "Encrypt Sensitive Data at Rest",
        "description": "Protect sensitive data with encryption at rest. Use strong, well-vetted encryption algorithms.",
        "ref_substring": "CIS v8 3",
    },
    {
        "section": "4.x",
        "title": "Secure Configuration",
        "description": "Establish and maintain a secure configuration process for enterprise assets and software.",
        "ref_substring": "CIS v8 4",
    },
    {
        "section": "5.x",
        "title": "Account Management",
        "description": "Use processes and tools to assign and manage authorisation to credentials for user accounts.",
        "ref_substring": "CIS v8 5",
    },
    {
        "section": "6.x",
        "title": "Access Control Management",
        "description": "Use processes and tools to create, assign, manage, and revoke access credentials and privileges.",
        "ref_substring": "CIS v8 6",
    },
    {
        "section": "8.x",
        "title": "Audit Log Management",
        "description": "Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.",
        "ref_substring": "CIS v8 8",
    },
    {
        "section": "16.x",
        "title": "Application Software Security",
        "description": "Manage the security life cycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses.",
        "ref_substring": "CIS v8 16",
    },
]


def scan_cis(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    """Scan a file for CIS Critical Security Controls v8 violations."""
    from app.services import rules_store

    issues: List[Issue] = []
    lines = content.splitlines()
    for rule in rules_store.get_active_rules(scanner="cis"):
        if "\\n" in rule.pattern or "\n" in rule.pattern:
            m = re.search(rule.pattern, content, re.MULTILINE | re.DOTALL)
            if not m:
                continue
            line_num = content[: m.start()].count("\n") + 1
            issues.append(Issue(
                category=Category.SECURITY,
                severity=rule.severity,
                file=relative_path,
                line=line_num,
                description=rule.description,
                recommendation=rule.recommendation,
                compliance_ref=rule.compliance_ref,
                source="cis_scanner",
                rule_id=rule.id,
            ))
            continue

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
                    source="cis_scanner",
                    rule_id=rule.id,
                ))
    return issues


def build_cis_checklist(all_issues: List[Issue]) -> List[ComplianceChecklistItem]:
    """Map CIS-tagged findings to control sections."""
    checklist: List[ComplianceChecklistItem] = []
    for item in CIS_CHECKLIST_TEMPLATE:
        relevant = [
            i for i in all_issues
            if i.compliance_ref and item["ref_substring"] in i.compliance_ref
        ]
        worst_idx = max(
            (SEVERITY_ORDER.index(i.severity.value) for i in relevant),
            default=-1,
        )
        checklist.append(ComplianceChecklistItem(
            framework="CIS Controls v8",
            section=item["section"],
            title=item["title"],
            description=item["description"],
            findings_count=len(relevant),
            status="fail" if relevant else "pass",
            worst_severity=SEVERITY_ORDER[worst_idx] if worst_idx >= 0 else None,
        ))
    return checklist
