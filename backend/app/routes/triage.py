"""AI triage routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.ai_triage import TriageService
from app.database import get_db
from app.models import Finding
from app.schemas.schemas import FindingOut, TriageResult

router = APIRouter(prefix="/findings", tags=["triage"])


@router.post("/{finding_id}/triage", response_model=FindingOut)
def triage_finding(finding_id: int, db: Session = Depends(get_db)):
    """Run AI triage and persist the enriched finding."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    service = TriageService()
    service.triage_finding(db, finding, apply=True)
    return finding


@router.post("/{finding_id}/triage/preview", response_model=TriageResult)
def preview_triage(finding_id: int, db: Session = Depends(get_db)):
    """Return triage results without persisting them."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    service = TriageService()
    return service.triage_finding(db, finding, apply=False)
