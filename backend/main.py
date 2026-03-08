from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from .config import settings
from .deps import SessionLocal, init_db
from .ratelimit import limiter
from .routers import auth, badge, billing, findings, reports, scans, waitlist
from .routers.v1 import benchmark, ingest, orgs, repos

app = FastAPI(
    title="Misconfig Index API",
    version="0.2.0",
    description=(
        "IaC misconfiguration scoring API — "
        "scan, score, and benchmark cloud security posture."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Rate limiting ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup() -> None:
    """
    1. Create all DB tables if they don't exist (safe for first-run on PostgreSQL).
    2. Upsert all scanner rules so FK constraints are satisfied on ingest.
    """
    init_db()

    from . import crud
    db = SessionLocal()
    try:
        crud._sync_rules(db)
    finally:
        db.close()


# ── Meta endpoints ────────────────────────────────────────────────────────────
@app.api_route("/health", methods=["GET", "HEAD"], tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.ENVIRONMENT}



# ── Routers ───────────────────────────────────────────────────────────────────

# Public / legacy endpoints
app.include_router(reports.router, prefix="/reports", tags=["reports"])
app.include_router(findings.router, prefix="/findings", tags=["findings"])
app.include_router(scans.router, prefix="/scans", tags=["scans"])

# v1 API (authenticated via X-API-Key)
app.include_router(orgs.router, prefix="/v1/orgs", tags=["v1 / orgs"])
app.include_router(ingest.router, prefix="/v1/ingest", tags=["v1 / ingest"])
app.include_router(repos.router, prefix="/v1/repos", tags=["v1 / repos"])
app.include_router(benchmark.router, prefix="/v1/benchmark", tags=["v1 / benchmark"])

# Public badge endpoint (no auth — for README embedding)
app.include_router(badge.router, prefix="/badge", tags=["badge"])

# GitHub OAuth + JWT auth
app.include_router(auth.router, prefix="/auth", tags=["auth"])

# Stripe billing
app.include_router(billing.router, prefix="/billing", tags=["billing"])

# Pro waitlist (pre-LLC signup)
app.include_router(waitlist.router, prefix="/waitlist", tags=["waitlist"])
