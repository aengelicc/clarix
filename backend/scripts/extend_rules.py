"""One-off migration: extend rules.json with OWASP, CIS, and gap-fill rules.

Idempotent — running it again will detect rules whose IDs already exist
and skip them. Generated entries mirror what rules_store._seed() produces
on a fresh install, so a future re-seed (delete rules.json) keeps these.
"""
import json
import sys
from pathlib import Path

# Add backend/ to sys.path so we can import the app modules.
BACKEND = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND))

from app.services.owasp_top10 import OWASP_PATTERNS  # noqa: E402
from app.services.cis_controls import CIS_PATTERNS  # noqa: E402
from app.services.security import SECRET_PATTERNS, DANGEROUS_PATTERNS  # noqa: E402

RULES_FILE = BACKEND / "app" / "data" / "rules.json"


# Gap-fill rules in the existing 5 frameworks.
# (scanner, name, pattern, severity, compliance_ref, recommendation, language, rule_type)
GAP_FILLS = [
    # --- Security scanner: extra secret patterns ---------------------------------
    (
        "security", "secret", "JWT Token in Source",
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "critical", None,
        "JWTs embedded in source are valid credentials. Move signing keys to a secrets manager; rotate any committed token.",
        "*",
    ),
    (
        "security", "secret", "Azure Storage Connection String",
        r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
        "critical", None,
        "Azure Storage account keys in source grant full read/write to the account. Use SAS tokens or Azure AD with managed identity.",
        "*",
    ),
    (
        "security", "secret", "Google Cloud API Key",
        r"AIza[0-9A-Za-z_-]{35}",
        "critical", None,
        "Google Cloud API keys in source grant access to the enabled GCP APIs. Restrict by HTTP referrer/IP, then move to a secrets manager.",
        "*",
    ),
    (
        "security", "secret", "OpenAI API Key",
        r"sk-(?!ant-)[A-Za-z0-9]{20,}",
        "critical", None,
        "OpenAI API keys in source grant access to your OpenAI account and billable usage. Move to environment variables or a secrets manager; rotate.",
        "*",
    ),
    (
        "security", "secret", "Anthropic API Key",
        r"sk-ant-[A-Za-z0-9-]{20,}",
        "critical", None,
        "Anthropic API keys in source grant access to your Claude account. Move to environment variables or a secrets manager; rotate.",
        "*",
    ),
    (
        "security", "secret", "Heroku API Key",
        r"(?i)heroku[_-]?(?:api[_-]?key|token)\s*[:=]\s*['\"][0-9a-f-]{36}['\"]",
        "high", None,
        "Heroku API keys grant full account access. Move to environment variables or a secrets manager.",
        "*",
    ),
    (
        "security", "secret", "Slack Incoming Webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "medium", None,
        "Slack incoming webhooks in source allow anyone to post into the channel. Store in env vars; treat as semi-secret and rotate if exposed.",
        "*",
    ),
    (
        "security", "secret", "Mailgun API Key",
        r"key-[0-9a-zA-Z]{32}",
        "high", None,
        "Mailgun API keys allow sending email as your domain. Move to environment variables or a secrets manager.",
        "*",
    ),

    # --- HIPAA gap-fills ---------------------------------------------------------
    (
        "hipaa", "compliance", "PHI Field Assignment Without Encryption Indicator",
        r'(?i)(?:phi|patient_?data|ePHI)\s*=\s*(?!.*(?:encrypt|cipher|aes))',
        "high", "§164.312(a)(2)(iii) — Encryption",
        "PHI assignment without a visible encryption step is likely plaintext storage. Wrap in an AES/cipher helper before assignment or storage.",
        "*",
    ),
    (
        "hipaa", "compliance", "No Audit Log on Authentication Event",
        r'(?i)(?:def|function)\s+(?:login|authenticate|signin|sign_in|verify_?token)\s*\([^)]*\):\s*\n(?!\s*(?:log|audit|logger|logging))',
        "medium", "§164.308(a)(6) — Security Incident Procedures",
        "Authentication events are reportable security incidents and must be logged. Emit an audit log entry on success and failure.",
        "*",
    ),
    (
        "hipaa", "compliance", "Backup Routine Without Encryption Indicator",
        r'(?i)(?:backup|export|dump)\s*\([^)]*(?:patient|phi|ePHI|medical|encounter)',
        "low", "§164.308(a)(7) — Contingency Plan",
        "Backups containing ePHI must be encrypted at rest and stored with restricted access. Verify your backup pipeline uses encrypted storage.",
        "*",
    ),

    # --- PCI gap-fills ------------------------------------------------------------
    (
        "pci", "compliance", "Test Card Number in Source",
        r"\b(?:4242424242424242|4000000000000002|5555555555554444|378282246310005|6011111111111117)\b",
        "critical", "PCI-DSS Req 6.4.3 — Production Data Not Used in Testing",
        "Well-known test card numbers in production code can be confused with real PANs. Use the official processor test numbers behind a strict environment check.",
        "*",
    ),
    (
        "pci", "compliance", "CSRF Protection Disabled",
        r'(?i)csrf_exempt\s*=\s*True|@csrf_exempt|CSRFProtect\s*\(\s*enabled\s*=\s*False',
        "high", "PCI-DSS Req 6.5 — Cross-Site Request Forgery",
        "CSRF protection must be enabled on all state-changing endpoints. Use synchronizer tokens, SameSite cookies, or double-submit cookies.",
        "*",
    ),

    # --- GDPR gap-fills -----------------------------------------------------------
    (
        "gdpr", "compliance", "Missing Right-to-Erasure Implementation",
        r'(?i)(?:def|function)\s+delete_(?:user|customer|account|profile|record)\s*\([^)]*\):\s*\n(?!\s*(?:anonymize|pseudonymize|gdpr|consent|retention))',
        "medium", "GDPR Art. 17 — Right to Erasure",
        "Delete handlers must anonymise, not just remove, personal data from backups and downstream systems. Implement a verified erasure flow.",
        "*",
    ),
    (
        "gdpr", "compliance", "Third-Party SDK With Personal Data",
        r'(?i)(?:mixpanel|amplitude|segment|hotjar|fullstory|intercom)\.identify\s*\(\s*[^)]*(?:email|user_id|customer_id|phone)',
        "high", "GDPR Art. 28 — Processor Obligations",
        "Sending personal identifiers to third-party analytics requires a Data Processing Agreement and a legal basis. Verify DPA exists before identifying users.",
        "*",
    ),

    # --- SOC 2 gap-fills ----------------------------------------------------------
    (
        "soc2", "compliance", "MFA Bypass Flag",
        r'(?i)(?:skip_mfa|bypass_mfa|mfa_disabled|disable_mfa|require_mfa\s*=\s*False)',
        "critical", "SOC 2 CC6.1 — Logical Access Controls",
        "MFA bypass flags must never be deployed. Remove entirely; use environment-gated feature flags if you need a non-prod override.",
        "*",
    ),
    (
        "soc2", "compliance", "Security Header Disabled",
        r'(?i)(?:X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy)\s*[=:]\s*(?:False|None|off|0|disabled)',
        "medium", "SOC 2 CC6.6 — External Threats",
        "Security headers protect against clickjacking, MIME sniffing, and protocol downgrade. Re-enable each header at the framework or proxy layer.",
        "*",
    ),
]


def existing_ids(rules):
    return {r["id"] for r in rules}


def add_pattern_rule(rules, scanner, rule_type, name, pattern, severity, ref, recommendation, language, rule_id):
    rules.append({
        "id": rule_id,
        "name": name,
        "pattern": pattern,
        "severity": severity,
        "description": f"{name} — {ref}." if ref else f"Potential secret detected: {name}. This may be a hardcoded credential.",
        "recommendation": recommendation,
        "language": language,
        "scanner": scanner,
        "rule_type": rule_type,
        "compliance_ref": ref,
        "enabled": True,
        "builtin": True,
    })


def main():
    rules = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    ids = existing_ids(rules)
    added = 0

    # OWASP rules -------------------------------------------------------------
    for i, (name, pattern, severity, ref, recommendation) in enumerate(OWASP_PATTERNS):
        rule_id = f"owasp-{i:03d}"
        if rule_id in ids:
            continue
        add_pattern_rule(
            rules, "owasp", "compliance", name, pattern, severity.value, ref, recommendation, "*", rule_id,
        )
        ids.add(rule_id)
        added += 1

    # CIS rules ---------------------------------------------------------------
    for i, (name, pattern, severity, ref, recommendation) in enumerate(CIS_PATTERNS):
        rule_id = f"cis-{i:03d}"
        if rule_id in ids:
            continue
        add_pattern_rule(
            rules, "cis", "compliance", name, pattern, severity.value, ref, recommendation, "*", rule_id,
        )
        ids.add(rule_id)
        added += 1

    # Gap-fill rules ----------------------------------------------------------
    # Track next available gap-fill index per scanner (0-based, padded to 3 digits).
    ID_PREFIX = {"security": "sec", "hipaa": "hipaa", "pci": "pci", "gdpr": "gdpr", "soc2": "soc2"}
    gap_index = {scanner: 0 for scanner in ID_PREFIX}
    for scanner, rule_type, name, pattern, severity, ref, recommendation, language in GAP_FILLS:
        i = gap_index[scanner]
        rule_id = f"{ID_PREFIX[scanner]}-x-{i:03d}"
        gap_index[scanner] = i + 1
        if rule_id in ids:
            continue
        add_pattern_rule(
            rules, scanner, rule_type, name, pattern, severity, ref, recommendation, language, rule_id,
        )
        ids.add(rule_id)
        added += 1

    RULES_FILE.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Added {added} new rules. Total: {len(rules)}.")

    # Sanity-check the JSON is still valid
    json.loads(RULES_FILE.read_text(encoding="utf-8"))
    print("JSON re-parse: OK")


if __name__ == "__main__":
    main()
