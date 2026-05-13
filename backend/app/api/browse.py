"""Native folder picker endpoint (macOS via osascript)."""
import subprocess
import sys
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.post("/browse-folder")
def browse_folder():
    if sys.platform != "darwin":
        raise HTTPException(status_code=400, detail="Folder browser only supported on macOS")
    result = subprocess.run(
        ["osascript", "-e",
         'tell app "Finder" to set f to choose folder\nreturn POSIX path of f'],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        # User cancelled or error
        raise HTTPException(status_code=204, detail="No folder selected")
    return {"path": result.stdout.strip()}
