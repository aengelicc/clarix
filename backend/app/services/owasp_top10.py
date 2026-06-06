"""OWASP Top 10 (2021) compliance scanning.

Covers the code-scannable subset of the OWASP Top 10 web application security
risks. Rules that overlap with HIPAA/SOC 2/PII scanners are included here under
the OWASP category reference so the OWASP view is substantively useful on its
own, not just an alias of another framework.
"""
from pathlib import Path
from typing import List

from app.core.models import Issue, ComplianceChecklistItem, Severity, Category, SEVERITY_ORDER
from app.services.scanner_common import scan_rules


# (name, pattern, severity, owasp_ref, recommendation)
OWASP_PATTERNS = [
    # --- A01:2021 — Broken Access Control ----------------------------------
    (
        "IDOR — Direct Object Reference from Request",
        r'(?i)(?:\.get|\.find|\.filter|WHERE)\s*\(?.*(?:id|user_id|record_id|order_id)\s*=\s*(?:request|req)\.\w+',
        Severity.HIGH,
        "A01:2021 — Broken Access Control",
        "Verify record ownership against the authenticated user before returning the object. Map incoming IDs to a permission check.",
    ),
    (
        "CORS Wildcard Origin",
        r'(?i)allow_origins?\s*=.*\*|Access-Control-Allow-Origin.+\*',
        Severity.HIGH,
        "A01:2021 — Broken Access Control",
        "Wildcard CORS grants any origin access. Replace * with an explicit allow-list of trusted origins.",
    ),
    (
        "Hardcoded Admin/Role Bypass",
        r'(?i)(?:is_admin|is_superuser|role)\s*=\s*[\'"]?(?:true|admin|superuser|root)[\'"]?',
        Severity.CRITICAL,
        "A01:2021 — Broken Access Control",
        "Hardcoded role flags in source defeat access control. Use a real RBAC system; remove the literal and load the role from the authenticated session.",
    ),
    (
        "Route Handler Without Auth Decorator (Flask/FastAPI)",
        r'@app\.(?:route|get|post|put|delete|patch)\s*\(\s*[\'"][^\'"]*(?:admin|manage|delete|user|account)[^\'"]*[\'"]\s*\)\s*\n\s*def\s+\w+',
        Severity.MEDIUM,
        "A01:2021 — Broken Access Control",
        "Sensitive route handler appears to lack an authentication/authorization decorator. Add @login_required / Depends(auth) / equivalent.",
    ),

    # --- A02:2021 — Cryptographic Failures ---------------------------------
    (
        "Weak Hash (MD5/SHA-1) for Sensitive Data",
        r'hashlib\.(md5|sha1)\s*\(',
        Severity.HIGH,
        "A02:2021 — Cryptographic Failures",
        "MD5 and SHA-1 are cryptographically broken. Use SHA-256+ for integrity and bcrypt/argon2/scrypt for password storage.",
    ),
    (
        "Prohibited Weak Cipher",
        r'(?i)\b(DES|3DES|Triple.?DES|RC4|RC2|MD4)\b',
        Severity.HIGH,
        "A02:2021 — Cryptographic Failures",
        "DES, 3DES, RC4, RC2, and MD4 are broken or deprecated. Use AES-256-GCM or ChaCha20-Poly1305.",
    ),
    (
        "Hardcoded Crypto IV or Nonce",
        r'(?i)(?:iv|nonce|salt)\s*=\s*b?[\'"][A-Za-z0-9+/=]{8,}[\'"]',
        Severity.HIGH,
        "A02:2021 — Cryptographic Failures",
        "Hardcoded IVs/nonces/salts destroy semantic security and enable replay attacks. Generate a fresh random value per operation.",
    ),
    (
        "TLS Verification Disabled",
        r'verify\s*=\s*False|ssl_verify\s*=\s*False|VERIFY_SSL\s*=\s*False|checkCertificate\s*=\s*false',
        Severity.HIGH,
        "A02:2021 — Cryptographic Failures",
        "Never disable TLS certificate verification. Disabling it exposes all transport data to man-in-the-middle attacks.",
    ),

    # --- A03:2021 — Injection ----------------------------------------------
    (
        "SQL Injection — String Concatenation in Query",
        r'(?i)(cursor\.execute|\.execute|\.raw)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?(%s|%d|\+\s*\w)',
        Severity.CRITICAL,
        "A03:2021 — Injection",
        "String-formatted SQL queries are injection-prone. Use parameterized queries or an ORM's bound parameters.",
    ),
    (
        "Command Injection — User Input in exec/popen",
        r'(?i)(?:os\.popen|subprocess\.(?:call|run|Popen)|child_process\.exec|execSync)\s*\(\s*[^)]*(?:\+|`|\$\(|\$\{)',
        Severity.CRITICAL,
        "A03:2021 — Injection",
        "Concatenating user input into a shell command enables command injection. Use argv arrays and validate/escape inputs, or call the binary directly with arguments.",
    ),
    (
        "NoSQL Injection — Unparameterized Query",
        r'(?i)(?:\.find|\.findOne|\.aggregate)\s*\(\s*\{[^}]*\+|(?:request|req)\.\w+.*\$(?:where|regex|expr)',
        Severity.HIGH,
        "A03:2021 — Injection",
        "User-controlled input injected into NoSQL queries can bypass filters and access controls. Use schema validation and sanitization.",
    ),
    (
        "LDAP Injection",
        r'(?i)(?:ldap_search|ldap_modify|search_s)\s*\(\s*[^,]*,\s*["\'].*?\+',
        Severity.HIGH,
        "A03:2021 — Injection",
        "User input concatenated into LDAP filters enables filter injection. Use parameterised LDAP filter construction.",
    ),
    (
        "XPath Injection",
        r'(?i)xpath\s*\(\s*["\'].*?\+',
        Severity.HIGH,
        "A03:2021 — Injection",
        "String-formatted XPath enables query manipulation. Use bound variables (xpath with a variables map) instead of concatenation.",
    ),
    (
        "innerHTML / outerHTML / document.write Assignment",
        r'innerHTML\s*[=+:]|outerHTML\s*[=+:]|document\.write\s*\(',
        Severity.MEDIUM,
        "A03:2021 — Injection",
        "Direct DOM assignment of unescaped data is an XSS sink. Set .textContent / use a framework's safe binding, or sanitise via DOMPurify.",
    ),

    # --- A05:2021 — Security Misconfiguration -----------------------------
    (
        "Debug Mode Enabled",
        r'DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True',
        Severity.MEDIUM,
        "A05:2021 — Security Misconfiguration",
        "Disable debug mode before deployment. Stack traces and verbose errors leak internals and may allow execution via debug consoles.",
    ),
    (
        "Verbose Error/Traceback Exposed",
        r'(?i)(?:@app\.errorhandler|@handler\.error)\s*\(\s*Exception\s*\)\s*\n\s*def\s+\w+[^:]*:\s*\n\s*(?:return|traceback|print)',
        Severity.MEDIUM,
        "A05:2021 — Security Misconfiguration",
        "Returning full tracebacks or exception text to clients leaks internals. Log full detail server-side; show a generic message to users.",
    ),
    (
        "Default or Weak Credential",
        r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'](?:password|Password|admin|123456|test|default|secret|changeme|12345|qwerty|root)["\']',
        Severity.HIGH,
        "A05:2021 — Security Misconfiguration",
        "Default/weak credentials must be replaced before deployment. Rotate on a defined schedule.",
    ),

    # --- A07:2021 — Authentication Failures --------------------------------
    (
        "Weak Session Token Generation (Math.random / random)",
        r'(?i)(?:Math\.random|\brandom\.(?:random|randint|choice|shuffle|sample))\s*\(',
        Severity.MEDIUM,
        "A07:2021 — Identification and Authentication Failures",
        "Math.random / Python random are not cryptographically secure. Use crypto.randomUUID(), secrets.token_urlsafe(), or secrets.token_hex() for session tokens.",
    ),
    (
        "Login Route Without Rate Limiting (heuristic)",
        r'(?i)(?:@app\.(?:route|post)|@router\.(?:post|route))\s*\(\s*[\'"][^\'"]*(?:login|signin|sign_in|authenticate)[\'"]',
        Severity.LOW,
        "A07:2021 — Identification and Authentication Failures",
        "Login endpoints require rate limiting and account lockout. Add throttling (e.g., slowapi, express-rate-limit) and consider MFA.",
    ),

    # --- A08:2021 — Software and Data Integrity Failures -------------------
    (
        "Insecure Deserialization (Python pickle / marshal)",
        r'pickle\.loads?\s*\(|marshal\.loads?\s*\(',
        Severity.CRITICAL,
        "A08:2021 — Software and Data Integrity Failures",
        "pickle/marshal.loads on untrusted data enables arbitrary code execution. Use json or a typed serializer; never unpickle attacker-controlled bytes.",
    ),
    (
        "Insecure Deserialization (Java ObjectInputStream / JavaScript eval)",
        r'ObjectInputStream.*readObject|node-serialize|serialize-javascript|eval\s*\(\s*JSON\.parse',
        Severity.CRITICAL,
        "A08:2021 — Software and Data Integrity Failures",
        "Deserialising untrusted Java objects or evaluating parsed JSON enables RCE/injection. Use allow-list type checks; never eval user data.",
    ),
    (
        "JWT Verify Disabled / Unsigned Algorithm",
        r'(?i)jwt\.(?:decode|verify)\s*\([^)]*(?:verify\s*=\s*False|algorithms\s*=\s*[\'"]none)|jwt\.decode\s*\([^)]*\)\s*$',
        Severity.CRITICAL,
        "A08:2021 — Software and Data Integrity Failures",
        "Disabling JWT signature verification or accepting alg=none allows forged tokens. Always verify with an explicit allow-list of algorithms (e.g., RS256).",
    ),
    (
        "Curl-Pipe-Shell (Insecure Update/Install)",
        r'(?i)(?:curl|wget|fetch)[^|]*\|\s*(?:sh|bash|zsh|sudo\s+sh|sudo\s+bash)',
        Severity.HIGH,
        "A08:2021 — Software and Data Integrity Failures",
        "Piping a remote download straight to a shell executes whatever the server returns. Download to a file, verify a checksum/signature, then execute.",
    ),

    # --- A09:2021 — Security Logging and Monitoring Failures --------------
    (
        "Silent Exception Swallowing",
        r'except\s*(?:Exception\s*)?\s*:\s*\n\s*pass\b|catch\s*\([^)]*\)\s*\{\s*\}',
        Severity.MEDIUM,
        "A09:2021 — Security Logging and Monitoring Failures",
        "Silent exception handling hides operational and security failures. Log the exception with context; alert on unexpected error rates.",
    ),
    (
        "Privileged Operation Without Audit Log",
        r'(?i)def\s+(?:delete_\w+|drop_\w+|purge_\w+|admin_\w+|revoke_\w+|destroy_\w+)\s*\([^)]*\):\s*\n(?!\s*(?:log|audit|logger|logging|print))',
        Severity.MEDIUM,
        "A09:2021 — Security Logging and Monitoring Failures",
        "Destructive and privileged operations must produce audit log entries. Log actor, action, timestamp, and affected resource ID.",
    ),

    # --- A10:2021 — Server-Side Request Forgery ---------------------------
    (
        "SSRF — User Input in HTTP Client URL",
        r'(?i)(?:requests?\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|httpx\.(?:get|post|client)|axios\.(?:get|post)|fetch\s*\()\s*\([^)]*(?:request|req)\.\w+',
        Severity.HIGH,
        "A10:2021 — Server-Side Request Forgery",
        "Passing request data directly to an HTTP client enables SSRF. Validate the URL against an allow-list of permitted hosts/schemes before issuing the request.",
    ),
    (
        "SSRF — User Input in Redirect / File Open",
        r'(?i)(?:redirect\s*\(\s*(?:request|req)\.\w+|open\s*\(\s*(?:request|req)\.\w+|send_file\s*\(\s*(?:request|req)\.\w+)',
        Severity.HIGH,
        "A10:2021 — Server-Side Request Forgery",
        "Using request data in redirects, file opens, or send_file allows local-file-read and SSRF. Resolve the path/URL to an absolute, validated target first.",
    ),
]


OWASP_CHECKLIST_TEMPLATE = [
    {
        "section": "A01:2021",
        "title": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
        "ref_substring": "A01:2021",
    },
    {
        "section": "A02:2021",
        "title": "Cryptographic Failures",
        "description": "Failures related to cryptography that lead to exposure of sensitive data.",
        "ref_substring": "A02:2021",
    },
    {
        "section": "A03:2021",
        "title": "Injection",
        "description": "Application is vulnerable when user-supplied data is not validated, filtered, or sanitised.",
        "ref_substring": "A03:2021",
    },
    {
        "section": "A05:2021",
        "title": "Security Misconfiguration",
        "description": "Missing appropriate security hardening, improperly configured permissions, default accounts, verbose errors.",
        "ref_substring": "A05:2021",
    },
    {
        "section": "A07:2021",
        "title": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is critical.",
        "ref_substring": "A07:2021",
    },
    {
        "section": "A08:2021",
        "title": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that do not protect against integrity violations, e.g., insecure deserialisation, CI/CD without integrity checks.",
        "ref_substring": "A08:2021",
    },
    {
        "section": "A09:2021",
        "title": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging and monitoring impedes detection of breaches and incident response.",
        "ref_substring": "A09:2021",
    },
    {
        "section": "A10:2021",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur when fetching a remote resource without validating the user-supplied URL.",
        "ref_substring": "A10:2021",
    },
]


def scan_owasp(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    """Scan a file for OWASP Top 10 (2021) violations."""
    return scan_rules(relative_path, language, content, scanner="owasp")


def build_owasp_checklist(all_issues: List[Issue]) -> List[ComplianceChecklistItem]:
    """Map OWASP-tagged findings to category sections."""
    checklist: List[ComplianceChecklistItem] = []
    for item in OWASP_CHECKLIST_TEMPLATE:
        relevant = [
            i for i in all_issues
            if i.compliance_ref and item["ref_substring"] in i.compliance_ref
        ]
        worst_idx = max(
            (SEVERITY_ORDER.index(i.severity.value) for i in relevant),
            default=-1,
        )
        checklist.append(ComplianceChecklistItem(
            framework="OWASP Top 10",
            section=item["section"],
            title=item["title"],
            description=item["description"],
            findings_count=len(relevant),
            status="fail" if relevant else "pass",
            worst_severity=SEVERITY_ORDER[worst_idx] if worst_idx >= 0 else None,
        ))
    return checklist
