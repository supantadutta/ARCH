"""FastAPI application entrypoint for AutoBugHunter.

Exposes the full REST API and Swagger documentation at ``/docs``. On startup it
ensures the database schema exists (Alembic is the source of truth for
migrations, but ``create_all`` keeps the dev experience smooth).

Strict authorization (API key) is applied to every API router, and consistent
error handling turns policy violations and validation errors into clean,
actionable JSON responses.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.auth import require_api_key
from app.config import settings
from app.database import Base, engine
from app.policy.scope_guard import ScopeError
from app.routes import (
    assets,
    audit,
    dashboard,
    findings,
    programs,
    reports,
    retests,
    scans,
    scope,
    settings as settings_routes,
    triage,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("autobughunter")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Ensure tables exist for a smooth first-run experience.
    Base.metadata.create_all(bind=engine)
    logger.info(
        "AutoBugHunter API started. dry_run=%s auth_enabled=%s",
        settings.dry_run,
        settings.auth_enabled,
    )
    yield


app = FastAPI(
    title="AutoBugHunter API",
    version="0.1.0",
    description=(
        "Authorized-only automated bug bounty & vulnerability management platform. "
        "All scanning is gated by an explicit scope allowlist, a global kill switch, "
        "rate limiting and full audit logging. Dry-run is the default. "
        "Every request requires a valid 'X-API-Key' header when auth is enabled."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# Error handling — clean, consistent JSON for every failure mode.
# --------------------------------------------------------------------------
@app.exception_handler(ScopeError)
async def scope_error_handler(request: Request, exc: ScopeError) -> JSONResponse:
    """Out-of-scope / forbidden scan requests become 403 with the reason."""
    return JSONResponse(
        status_code=403,
        content={
            "error": "scope_violation",
            "detail": exc.decision.reason,
            "normalized_target": exc.decision.normalized_target,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Surface validation problems with readable field-level messages."""
    messages = [
        f"{'.'.join(str(p) for p in err['loc'][1:]) or 'body'}: {err['msg']}"
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "detail": messages},
    )


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:
    """Database constraint violations become a clean 400."""
    logger.warning("integrity error: %s", exc)
    return JSONResponse(
        status_code=400,
        content={"error": "integrity_error", "detail": "Request violates a data constraint."},
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler — never leak internals to the client."""
    logger.exception("unhandled error on %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "An unexpected error occurred."},
    )


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Unauthenticated liveness probe."""
    return {
        "status": "ok",
        "dry_run_default": settings.dry_run,
        "auth_enabled": settings.auth_enabled,
    }


# Every API router is mounted behind the API-key dependency — strict
# authorization is applied uniformly across the whole API surface.
_prefix = settings.api_v1_prefix
_auth = [Depends(require_api_key)]
for module in (
    programs,
    scope,
    assets,
    scans,
    findings,
    triage,
    reports,
    retests,
    audit,
    settings_routes,
    dashboard,
):
    app.include_router(module.router, prefix=_prefix, dependencies=_auth)
