"""API routes for false-positive mark management."""
from fastapi import APIRouter, HTTPException

from app.core.fp_models import FPMark, FPMarkCreate, FPMarkList
from app.services import fp_store

router = APIRouter()


@router.get("/fp-marks", response_model=FPMarkList)
def list_fp_marks():
    """List every FP mark currently persisted."""
    raw = fp_store.list_marks()
    return FPMarkList(
        marks=[FPMark(**m) for m in raw],
        count=len(raw),
    )


@router.post("/fp-marks", response_model=FPMark, status_code=201)
def add_fp_mark(body: FPMarkCreate):
    """Add an FP mark. Idempotent — re-adding the same mark returns the existing one."""
    try:
        mark = fp_store.add_mark(
            file_path=body.file_path,
            reason=body.reason,
            rule_id=body.rule_id,
            description_hash=body.description_hash,
            marked_by=body.marked_by,
        )
    except ValueError as e:
        # Validation: file_path required, exactly one of rule_id / description_hash
        raise HTTPException(status_code=400, detail=str(e)) from e
    return FPMark(**mark)


@router.delete("/fp-marks/{mark_id}", status_code=204)
def remove_fp_mark(mark_id: str):
    """Remove an FP mark by id. Returns 404 if the mark doesn't exist."""
    removed = fp_store.remove_mark(mark_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"FP mark {mark_id!r} not found")
    return None
