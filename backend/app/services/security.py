"""Security scanning: secrets and dangerous patterns."""
import re
from pathlib import Path
from typing import List
from app.core.models import Issue, Severity, Category


SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("AWS Secret Key", r"""['"][0-9a-zA-Z/+]{40}['"]""", Severity.CRITICAL),
    ("Generic API Key", r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-z0-9_\-]{16,}['"]""", Severity.HIGH),
    ("Generic Secret", r"""(?i)(secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]""", Severity.HIGH),
    ("Private Key", r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("GitHub PAT", r"ghp_[a-zA-Z0-9]{36}", Severity.CRITICAL),
    ("Slack Token", r"xox[baprs]-[a-zA-Z0-9]{10,48}", Severity.CRITICAL),
    ("Bearer Token", r"(?i)bearer\s+[a-z0-9_\-\.]{20,}", Severity.HIGH),
    ("Connection String", r"(?i)(mongodb|mysql|postgresql|postgres|redis)://[^:]+:[^@]+@", Severity.HIGH),
]

DANGEROUS_PATTERNS = {
    "Python": [
        (r"eval\s*\(", "Use of eval() can lead to arbitrary code execution.", Severity.HIGH),
        (r"exec\s*\(", "Use of exec() can lead to arbitrary code execution.", Severity.HIGH),
        (r"subprocess\.call\s*\([^)]*shell\s*=\s*True", "subprocess with shell=True is dangerous with untrusted input.", Severity.HIGH),
        (r"os\.system\s*\(", "os.system() is dangerous and should be replaced with subprocess.", Severity.MEDIUM),
        (r"pickle\.loads?\s*\(", "pickle can execute arbitrary code during deserialization.", Severity.HIGH),
        (r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader", "yaml.load with yaml.Loader is unsafe. Use SafeLoader.", Severity.HIGH),
        (r"input\s*\([^)]*\)\s*eval", "User input passed to eval() is a critical security risk.", Severity.CRITICAL),
        (r"DEBUG\s*=\s*True", "DEBUG=True should not be used in production.", Severity.MEDIUM),
        (r"VERIFY_SSL\s*=\s*False|verify\s*=\s*False", "SSL verification disabled. This exposes the app to MITM attacks.", Severity.HIGH),
    ],
    "JavaScript": [
        (r"eval\s*\(", "eval() is dangerous and should be avoided.", Severity.HIGH),
        (r"""Function\s*\(\s*['"]""", "Dynamic Function constructor is similar to eval().", Severity.HIGH),
        (r"innerHTML\s*[=+:]", "innerHTML assignment can lead to XSS if user input is involved.", Severity.MEDIUM),
        (r"document\.write\s*\(", "document.write() is dangerous and deprecated.", Severity.MEDIUM),
        (r"\.exec\s*\(", "exec() with user input can lead to command injection.", Severity.HIGH),
    ],
    "TypeScript": [
        (r"eval\s*\(", "eval() is dangerous and should be avoided.", Severity.HIGH),
        (r"innerHTML\s*[=+:]", "innerHTML assignment can lead to XSS if user input is involved.", Severity.MEDIUM),
    ],
    "Java": [
        (r"Runtime\.getRuntime\(\)\.exec", "Runtime.exec() can lead to command injection with unsanitized input.", Severity.HIGH),
        (r"ObjectInputStream.*readObject", "Deserializing untrusted data can lead to remote code execution.", Severity.HIGH),
    ],
    "Go": [
        (r"exec\.CommandContext?\s*\(", "Command execution with user input can lead to command injection.", Severity.MEDIUM),
    ],
    "Shell": [
        (r"\$\(", "Command substitution can be dangerous with untrusted input.", Severity.MEDIUM),
        (r"eval\s", "eval in shell scripts is dangerous.", Severity.HIGH),
    ],
}

DEPENDENCY_FILES = {
    "requirements.txt": "Python dependencies",
    "Pipfile": "Python dependencies",
    "poetry.lock": "Python dependencies",
    "package.json": "Node.js dependencies",
    "package-lock.json": "Node.js dependencies",
    "yarn.lock": "Node.js dependencies",
    "pom.xml": "Java Maven dependencies",
    "build.gradle": "Java Gradle dependencies",
    "go.mod": "Go dependencies",
    "Cargo.toml": "Rust dependencies",
    "Gemfile": "Ruby dependencies",
    "composer.json": "PHP dependencies",
}


def scan_file(file_path: Path, relative_path: str, language: str, content: str) -> List[Issue]:
    from app.services import rules_store
    issues = []
    lines = content.splitlines()

    for rule in rules_store.get_active_rules(scanner="security", rule_type="secret"):
        for i, line in enumerate(lines, 1):
            if re.search(rule.pattern, line):
                stripped = line.strip().lower()
                if stripped.startswith(("#", "//", "*")):
                    continue  # skip comment lines — they're documentation, not live credentials
                issues.append(Issue(
                    category=Category.SECURITY,
                    severity=rule.severity,
                    file=relative_path,
                    line=i,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    code_snippet=line.strip()[:150],
                    source="security_scanner",
                ))

    for rule in rules_store.get_active_rules(scanner="security", rule_type="dangerous"):
        if rule.language not in ("*", language):
            continue
        for i, line in enumerate(lines, 1):
            if re.search(rule.pattern, line):
                issues.append(Issue(
                    category=Category.SECURITY,
                    severity=rule.severity,
                    file=relative_path,
                    line=i,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    code_snippet=line.strip()[:150],
                    source="security_scanner",
                ))

    return issues


def check_dependencies(repo_path: str) -> List[Issue]:
    issues = []
    repo = Path(repo_path)
    for dep_file, dep_type in DEPENDENCY_FILES.items():
        if (repo / dep_file).exists():
            issues.append(Issue(
                category=Category.SECURITY,
                severity=Severity.MEDIUM,
                file=dep_file,
                line=None,
                description=f"{dep_type} file found. Dependencies may contain known vulnerabilities.",
                recommendation="Run vulnerability scan: pip-audit / npm audit / OWASP Dependency-Check. Review and update outdated packages before deployment.",
                source="security_scanner"
            ))
    return issues
