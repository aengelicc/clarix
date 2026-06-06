"""File system utilities."""
import os
import pathspec
from pathlib import Path
from typing import List, Tuple, Optional

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".cpp", ".c", ".h",
    ".cs", ".rb", ".php", ".swift", ".kt", ".scala", ".r", ".m", ".mm", ".sql",
    ".sh", ".bash", ".ps1", ".yaml", ".yml", ".json", ".xml", ".tf", ".dockerfile",
    ".md", ".rst", ".ini", ".cfg", ".toml"
}

LANGUAGE_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "React JSX",
    ".tsx": "React TSX", ".java": "Java", ".go": "Go", ".rs": "Rust",
    ".cpp": "C++", ".c": "C", ".h": "C/C++ Header", ".cs": "C#",
    ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".kt": "Kotlin",
    ".scala": "Scala", ".r": "R", ".sql": "SQL", ".sh": "Shell",
    ".bash": "Bash", ".ps1": "PowerShell", ".yaml": "YAML", ".yml": "YAML",
    ".json": "JSON", ".xml": "XML", ".tf": "Terraform", ".dockerfile": "Dockerfile",
    ".md": "Markdown", ".rst": "reStructuredText", ".ini": "INI", ".cfg": "Config",
    ".toml": "TOML"
}

SKIP_DIRS = {
    "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    ".git", ".github", ".vscode", ".idea", "target", "vendor", "coverage",
    "htmlcov", ".tox", ".pytest_cache", ".mypy_cache"
}


def load_gitignore_specs(repo_path: str) -> Optional[pathspec.PathSpec]:
    gitignore_path = Path(repo_path) / ".gitignore"
    if gitignore_path.exists():
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return pathspec.PathSpec.from_lines("gitwildmatch", lines)
    return None


def is_code_file(file_path: Path) -> bool:
    if file_path.name.lower() == "dockerfile":
        return True
    return file_path.suffix.lower() in CODE_EXTENSIONS


def detect_language(file_path: Path) -> str:
    name = file_path.name.lower()
    if name == "dockerfile":
        return "Dockerfile"
    return LANGUAGE_MAP.get(file_path.suffix.lower(), "Unknown")


def get_repo_files(repo_path: str, max_file_size_kb: int = 500, max_files: int = 100,
                   include_hidden: bool = False) -> List[Tuple[Path, str, int]]:
    repo_path = Path(repo_path).resolve()
    gitignore = load_gitignore_specs(str(repo_path))
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")
                   and (include_hidden or not d.startswith("."))]
        for filename in filenames:
            file_path = Path(root) / filename
            rel_path = file_path.relative_to(repo_path)
            rel_str = str(rel_path).replace("\\", "/")
            if gitignore and gitignore.match_file(rel_str):
                continue
            if not include_hidden and filename.startswith("."):
                continue
            if not is_code_file(file_path):
                continue
            size = file_path.stat().st_size
            if size > max_file_size_kb * 1024:
                continue
            lang = detect_language(file_path)
            files.append((rel_path, lang, size))
            if len(files) >= max_files:
                break  # inner loop — stops current directory immediately
        if len(files) >= max_files:
            break  # outer loop — stops walking further directories
    return files


def read_file_content(file_path: Path, max_chars: int = 50000) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_chars)
    except Exception as e:
        return f"[Error reading file: {e}]"


def count_lines(content: str) -> int:
    return len(content.splitlines())


def estimate_tokens(text: str) -> int:
    import math
    return math.ceil(len(text) / 4)
