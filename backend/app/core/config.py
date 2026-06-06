"""Application configuration via environment variables."""
from pathlib import Path

from pydantic_settings import BaseSettings

_HERE = Path(__file__).parent


class Settings(BaseSettings):
    llm_provider: str = "openai"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    github_pat: str | None = None

    # When set, all API endpoints require "Authorization: Bearer <token>"
    api_secret_token: str | None = None

    # Comma-separated list of allowed local base paths (empty = no restriction)
    allowed_local_paths: str | None = None

    # Analysis limits
    max_files: int = 100
    max_file_size_kb: int = 500
    max_file_tokens: int = 8000

    class Config:
        env_file = str(_HERE.parent.parent / ".env")
        env_file_encoding = "utf-8"


settings = Settings()
