"""Pydantic models for the false-positive tracking API."""
from pydantic import BaseModel, Field


class FPMarkCreate(BaseModel):
    """Body for POST /api/fp-marks.

    Exactly one of `rule_id` or `description_hash` must be set:
    - `rule_id` for a static-scanner FP (e.g. "sec-secret-001")
    - `description_hash` for an LLM-detected FP (sha256 of description)
    """
    file_path: str = Field(..., min_length=1, description="Relative file path the mark applies to")
    reason: str = Field(default="", description="Free-text note for the team")
    rule_id: str | None = Field(default=None, description="Static-scanner rule id (e.g. 'sec-secret-001')")
    description_hash: str | None = Field(
        default=None, description="sha256 of the LLM issue description; use fp_store.hash_description()"
    )
    marked_by: str = Field(default="user", description="Identity of the marker (user, ci, etc.)")


class FPMark(BaseModel):
    id: str
    file_path: str
    rule_id: str | None = None
    description_hash: str | None = None
    reason: str = ""
    marked_at: str
    marked_by: str = "user"


class FPMarkList(BaseModel):
    marks: list[FPMark]
    count: int
