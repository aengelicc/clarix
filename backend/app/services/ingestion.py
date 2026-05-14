"""Repository ingestion: GitHub clone and local path handling."""
import os
import re
import tempfile
import shutil
from pathlib import Path
from git import Repo
from urllib.parse import urlparse


def extract_repo_info(github_url: str) -> tuple:
    patterns = [
        r"github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"github\.com/([^/]+)/([^/]+?)(?:\.git)?/?.*"
    ]
    for pattern in patterns:
        match = re.search(pattern, github_url)
        if match:
            return match.group(1), match.group(2).replace(".git", "")
    return None, None


def normalize_github_url(github_url: str) -> str:
    github_url = github_url.strip().rstrip("/")
    if not github_url.endswith(".git"):
        github_url += ".git"
    return github_url


def clone_github_repo(github_url: str, pat: str = None) -> str:
    github_url = normalize_github_url(github_url)
    if pat:
        parsed = urlparse(github_url)
        auth_url = f"https://{pat}@{parsed.netloc}{parsed.path}"
        clone_url = auth_url
    else:
        clone_url = github_url
    temp_dir = tempfile.mkdtemp(prefix="codegate_gh_")
    try:
        Repo.clone_from(clone_url, temp_dir, depth=1, single_branch=True)
        return temp_dir
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {e}")


def cleanup_clone(path: str):
    if path and os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)


def validate_local_path(path: str) -> str:
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise ValueError(f"Path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"Path is not a directory: {resolved}")
    # Enforce allowlist when ALLOWED_LOCAL_PATHS is configured.
    from app.core.config import settings
    if settings.allowed_local_paths:
        allowed = [Path(p.strip()).resolve() for p in settings.allowed_local_paths.split(",") if p.strip()]
        if not any(resolved == base or resolved.is_relative_to(base) for base in allowed):
            raise ValueError(f"Path '{resolved}' is outside the configured allowed directories.")
    return str(resolved)


class RepoIngestor:
    def __init__(self, github_pat: str = None):
        self.github_pat = github_pat
        self.temp_clone_path = None
        self.source_type = None
        self.repo_name = None

    def ingest(self, source: str) -> tuple:
        if source.startswith("http://") or source.startswith("https://"):
            self.source_type = "github"
            owner, repo = extract_repo_info(source)
            self.repo_name = f"{owner}/{repo}" if owner and repo else "unknown_repo"
            self.temp_clone_path = clone_github_repo(source, self.github_pat)
            repo_path = self.temp_clone_path
        else:
            self.source_type = "local"
            repo_path = validate_local_path(source)
            self.repo_name = Path(repo_path).name
        return repo_path, self.source_type, self.repo_name

    def cleanup(self):
        if self.temp_clone_path:
            cleanup_clone(self.temp_clone_path)
            self.temp_clone_path = None
