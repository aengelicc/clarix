"""FastAPI application entry point."""

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.analysis import router as analysis_router
from app.api.browse import router as browse_router
from app.api.fp_marks import router as fp_marks_router
from app.api.rules import router as rules_router
from app.core.config import settings

_bearer = HTTPBearer(auto_error=False)


def _require_auth(credentials: HTTPAuthorizationCredentials | None = Security(_bearer)):
    """No-op when API_SECRET_TOKEN is unset; enforces bearer token otherwise."""
    token = settings.api_secret_token
    if not token:
        return
    if credentials is None or credentials.credentials != token:
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI(
    title="Clarix API",
    description="Pre-deployment code assessment backend",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

_auth_dep = [Depends(_require_auth)]

app.include_router(analysis_router, prefix="/api", tags=["analysis"], dependencies=_auth_dep)
app.include_router(browse_router, prefix="/api", tags=["browse"], dependencies=_auth_dep)
app.include_router(rules_router, prefix="/api", tags=["rules"], dependencies=_auth_dep)
app.include_router(fp_marks_router, prefix="/api", tags=["fp-marks"], dependencies=_auth_dep)


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "clarix-api"}
