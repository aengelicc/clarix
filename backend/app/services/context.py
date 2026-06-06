"""Cross-file context builder for the LLM analyst.

Why this exists: per-file mode sends one file at a time to the LLM. When
the file calls a helper from another module in the same repo, the LLM
sees the call site but not the helper body — so it can't tell whether
`authenticate(user, token)` actually validates the token, or whether
`lookup_patient(id)` does tenant scoping, or whether `hash_password`
is bcrypt or md5. This module pre-imports those helpers (up to a token
budget) and returns a context block the LLM call site can append.

Scope:
- Per-file mode only. Bundle mode already has the whole repo.
- Same-repo imports only. Third-party packages (`os`, `react`, `lodash`)
  are skipped — the LLM already knows them.
- Python imports via `ast` (accurate). JS/TS imports via regex (good
  enough for the common cases; an `import('foo')` dynamic import is
  skipped — those are runtime and we can't know what was imported).
- Relative imports (`from .foo import bar`, `import './foo'`) are
  resolved against the importing file's directory.
- Absolute imports that don't resolve to a file in the repo are
  silently skipped.

Budget: a soft cap. We walk the imports in order and accept each one
that fits within the remaining budget. Truncation strategy: take the
top N lines of each imported file (default 100), with a "..." suffix
if the file is longer. This keeps the context block readable.
"""

import ast
import re
from pathlib import Path

# Stdlib / well-known third-party packages we should never try to inline.
# If a same-repo project shadows one of these (e.g. local `import json` that
# happens to resolve to `./json.py`), the import resolver still wins because
# we'll prefer a same-repo match over a missing-on-disk package.
# (We don't try to be clever here — `os`, `sys`, `re` etc. are skipped
# categorically when they appear in an absolute import. Same-repo
# relative imports like `from . import utils` are always followed.)
_PYTHON_SKIP_MODULES: frozenset[str] = frozenset({
    # Python stdlib (most common)
    "os", "sys", "re", "json", "typing", "collections", "functools",
    "pathlib", "itertools", "math", "datetime", "time", "logging",
    "unittest", "asyncio", "threading", "subprocess",
    "shutil", "tempfile", "io", "abc", "enum", "dataclasses",
    "copy", "weakref", "operator", "contextlib", "warnings",
    "urllib", "http", "email", "html", "textwrap", "string",
    "struct", "socket", "ssl", "select", "signal", "multiprocessing",
    "concurrent", "queue", "heapq", "bisect", "array", "types",
    "importlib", "pkgutil", "traceback", "inspect", "dis",
    "token", "tokenize", "symtable", "compileall", "py_compile",
    "compile", "cgi", "cgitb", "wsgiref", "xmlrpc", "pydoc",
    "doctest", "difflib", "pdb", "profile", "pstats",
    "timeit", "sched", "calendar", "locale", "gettext", "unicodedata",
    "stringprep", "pprint", "reprlib", "graphlib", "tomllib",
    "configparser", "argparse", "getopt", "getpass", "curses",
    "platform", "errno", "faulthandler", "tracemalloc", "gc", "sysconfig",
    "site", "zipimport", "runpy",
    # Common third-party
    "numpy", "pandas", "scipy", "requests", "urllib3", "httpx", "aiohttp",
    "flask", "django", "fastapi", "uvicorn", "starlette", "pydantic",
    "sqlalchemy", "alembic", "psycopg2", "pymysql", "redis", "celery",
    "boto3", "botocore", "aws", "azure", "google", "openai", "anthropic",
    "torch", "tensorflow", "sklearn", "matplotlib", "seaborn", "plotly",
    "yaml", "toml", "click", "typer", "rich", "loguru", "structlog",
    "pytest", "hypothesis", "tox", "nox", "coverage", "mypy", "ruff",
    "black", "isort", "pylint", "flake8", "gitpython", "github",
    "pathspec", "pyyaml", "python_multipart", "python-dotenv", "dotenv",
})

# Per-file truncation: imports get a slice of this many top lines.
_IMPORT_TRUNCATE_LINES = 100


def estimate_tokens(text: str) -> int:
    """Cheap token estimator — same `len/4` heuristic used elsewhere."""
    import math
    return math.ceil(len(text) / 4)


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


def extract_python_imports(content: str) -> list[str]:
    """Return the module names referenced by `import x` / `from x import y`.

    Relative imports (`from .foo import bar`) are returned as `.foo` so the
    resolver can handle them with repo-relative path logic. stdlib and
    common third-party modules are filtered out.
    """
    imports: list[str] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in _PYTHON_SKIP_MODULES:
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                # `from . import foo` — node.module is None, names are relative
                # We keep the names; resolver handles them.
                for alias in node.names:
                    imports.append(f".{alias.name}")
            else:
                top = node.module.split(".")[0]
                if top in _PYTHON_SKIP_MODULES:
                    continue
                if node.level and node.level > 0:
                    prefix = "." * node.level
                    imports.append(f"{prefix}{node.module}")
                else:
                    imports.append(node.module)

    # Dedupe but preserve order
    seen: set[str] = set()
    deduped: list[str] = []
    for imp in imports:
        if imp not in seen:
            seen.add(imp)
            deduped.append(imp)
    return deduped


_JS_IMPORT_RE = re.compile(
    r"""
    (?:
        import\s+(?:[\w*\s{},]*\s+from\s+)?     # import x from 'y' / import { a, b } from 'y'
        ['"]([^'"]+)['"]                          # 'y' or "y"
        |
        require\(\s*['"]([^'"]+)['"]\s*\)         # const x = require('y')
        |
        import\(\s*['"]([^'"]+)['"]\s*\)          # dynamic import('y') — skip these
    )
    """,
    re.VERBOSE,
)


def extract_js_imports(content: str) -> list[str]:
    """Return the module specifiers referenced by JS/TS imports.

    Skips bare specifiers (third-party packages) and dynamic imports.
    Only relative specifiers (`./foo`, `../foo`) and same-dir absolute
    paths are kept for the resolver to chase.
    """
    imports: list[str] = []
    for match in _JS_IMPORT_RE.finditer(content):
        spec = match.group(1) or match.group(2) or match.group(3)
        if spec is None:
            continue
        if spec.startswith(".") or spec.startswith("/"):
            imports.append(spec)
    # Dedupe but preserve order
    seen: set[str] = set()
    deduped: list[str] = []
    for imp in imports:
        if imp not in seen:
            seen.add(imp)
            deduped.append(imp)
    return deduped


def extract_imports(language: str, content: str) -> list[str]:
    """Dispatch by language. Unknown languages return []."""
    lang = (language or "").lower()
    if lang in {"python", "py"}:
        return extract_python_imports(content)
    if lang in {"javascript", "typescript", "js", "ts", "jsx", "tsx"}:
        return extract_js_imports(content)
    return []


# ---------------------------------------------------------------------------
# Import resolution: specifier -> Path in the repo
# ---------------------------------------------------------------------------


def _resolve_python_import(repo_path: Path, importing_file: Path, module: str) -> Path | None:
    """Resolve a Python import string to a file path under repo_path.

    Handles:
    - Relative imports (`from .foo import bar` -> ./foo.py or ./foo/__init__.py)
    - Absolute same-repo imports (`from mypkg.utils import x` -> ./mypkg/utils.py)
    """
    if module.startswith("."):
        # Relative import — count dots for `..`, `...`, etc.
        level = len(module) - len(module.lstrip("."))
        remainder = module[level:]
        base = importing_file.parent
        for _ in range(level - 1):
            base = base.parent
        if remainder:
            parts = remainder.split(".")
            candidate = base.joinpath(*parts)
        else:
            candidate = base
    else:
        parts = module.split(".")
        candidate = repo_path.joinpath(*parts)

    # Try the common shapes: foo.py, foo/__init__.py, foo/index.py
    for path in (candidate.with_suffix(".py"), candidate / "__init__.py"):
        if path.is_file():
            return path
    return None


def _resolve_js_import(repo_path: Path, importing_file: Path, spec: str) -> Path | None:
    """Resolve a JS/TS import specifier to a file path under repo_path."""
    if spec.startswith("/"):
        base = repo_path
        rel = spec.lstrip("/")
    else:
        # Relative: strip leading "./" or "../" and step up
        base = importing_file.parent
        rel = spec
        while rel.startswith("../"):
            base = base.parent
            rel = rel[3:]
        if rel.startswith("./"):
            rel = rel[2:]

    candidate = base / rel
    # Try common extensions in order
    for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        with_ext = candidate.with_suffix(ext)
        if with_ext.is_file():
            return with_ext
    # Maybe spec ends in .js/.ts already
    if candidate.is_file():
        return candidate
    # Maybe it's a directory with an index file
    for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        idx = candidate / f"index{ext}"
        if idx.is_file():
            return idx
    return None


def resolve_import(
    repo_path: Path, importing_file: Path, spec: str, language: str
) -> Path | None:
    """Resolve an import specifier to a file under repo_path, or None."""
    lang = (language or "").lower()
    if lang in {"python", "py"}:
        return _resolve_python_import(repo_path, importing_file, spec)
    if lang in {"javascript", "typescript", "js", "ts", "jsx", "tsx"}:
        return _resolve_js_import(repo_path, importing_file, spec)
    return None


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------


def _read_capped(path: Path, max_lines: int = _IMPORT_TRUNCATE_LINES) -> str:
    """Read up to `max_lines` lines of a file. Returns "" on read error."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    lines.append(f"... [truncated at {max_lines} of {path.name}]")
                    break
                lines.append(line.rstrip("\n"))
            return "\n".join(lines)
    except OSError:
        return ""


def build_context_for_file(
    repo_path: Path,
    importing_file: Path,
    language: str,
    content: str,
    max_tokens: int,
) -> str:
    """Return a context block (markdown-fenced) listing the imported files,
    up to `max_tokens` of context. Returns "" if there are no imports to
    follow or the budget is 0.
    """
    if max_tokens <= 0:
        return ""
    specs = extract_imports(language, content)
    if not specs:
        return ""

    sections: list[str] = []
    tokens_used = 0
    seen: set[Path] = set()
    # Header + footer overhead
    header = "\n## Imported Context\n\nThe following definitions are imported into this file. Review them alongside the main content for accuracy.\n\n"
    tokens_used += estimate_tokens(header)
    tokens_used += 8  # footer budget

    for spec in specs:
        target = resolve_import(repo_path, importing_file, spec, language)
        if target is None or target in seen:
            continue
        seen.add(target)
        snippet = _read_capped(target)
        if not snippet:
            continue
        section = f"### `{spec}` (from `{target.name}`)\n\n```\n{snippet}\n```\n\n"
        cost = estimate_tokens(section)
        if tokens_used + cost > max_tokens:
            # Try a shorter truncation
            shorter = _read_capped(target, max_lines=30)
            if shorter != snippet:
                section = f"### `{spec}` (from `{target.name}`)\n\n```\n{shorter}\n```\n\n"
                cost = estimate_tokens(section)
            if tokens_used + cost > max_tokens:
                continue  # skip this one entirely
        sections.append(section)
        tokens_used += cost
        if tokens_used >= max_tokens:
            break

    if not sections:
        return ""
    return header + "".join(sections)
