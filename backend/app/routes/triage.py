"""AI triage routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.ai_triage import AITriageError, TriageService, available_providers, get_provider
from app.config import settings
from app.database import get_db
from app.models import Finding
from app.schemas.schemas import FindingOut, TriageResult

router = APIRouter(prefix="/findings", tags=["triage"])


@router.post("/{finding_id}/triage", response_model=FindingOut)
def triage_finding(finding_id: int, provider: str | None = None, db: Session = Depends(get_db)):
    """Run AI triage and persist the enriched finding.

    ``provider`` optionally overrides the configured provider (mock/openai/local).
    """
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    service = TriageService(provider=get_provider(provider) if provider else None)
    try:
        service.triage_finding(db, finding, apply=True)
    except AITriageError as exc:
        # Provider unavailable / misconfigured — surface a clean 502.
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return finding


@router.post("/{finding_id}/triage/preview", response_model=TriageResult)
def preview_triage(finding_id: int, provider: str | None = None, db: Session = Depends(get_db)):
    """Return triage results without persisting them."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    service = TriageService(provider=get_provider(provider) if provider else None)
    try:
        return service.triage_finding(db, finding, apply=False)
    except AITriageError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/{finding_id}/triage/structured")
def structured_triage(finding_id: int, provider: str | None = None, db: Session = Depends(get_db)):
    """Return the canonical structured triage JSON (exact required keys)."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    service = TriageService(provider=get_provider(provider) if provider else None)
    try:
        result = service.triage_finding(db, finding, apply=False)
    except AITriageError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return result.to_structured_json()


@router.get("/triage/providers")
def list_providers():
    """List available triage providers and the active one."""
    return {"active": settings.ai_provider, "providers": available_providers()}
