"""FastAPI application entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analysis import router as analysis_router
from app.api.browse import router as browse_router
from app.api.rules import router as rules_router

app = FastAPI(
    title="Clarix API",
    description="Pre-deployment code assessment backend",
    version="1.0.0"
)

# CORS - allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis_router, prefix="/api", tags=["analysis"])
app.include_router(browse_router, prefix="/api", tags=["browse"])
app.include_router(rules_router, prefix="/api", tags=["rules"])

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "clarix-api"}
