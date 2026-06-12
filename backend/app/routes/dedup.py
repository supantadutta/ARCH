"""Duplicate-detection routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.dedup import deduplicate_finding, deduplicate_program, find_duplicate_candidates
from app.models import Finding, Program
from app.schemas.schemas import FindingOut

router = APIRouter(tags=["dedup"])


@router.get("/findings/{finding_id}/duplicates")
def list_duplicate_candidates(finding_id: int, db: Session = Depends(get_db)):
    """Return candidate duplicates for a finding (read-only, no changes)."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    matches = find_duplicate_candidates(db, finding)
    return {
        "finding_id": finding_id,
        "candidates": [
            {"finding_id": m.finding_id, "title": m.title, "score": m.score, "reasons": m.reasons}
            for m in matches
        ],
    }


@router.post("/findings/{finding_id}/deduplicate", response_model=FindingOut)
def deduplicate_one(
    finding_id: int,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    """Link this finding to the earliest matching duplicate, if any."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    deduplicate_finding(db, finding, actor=actor)
    return finding


@router.post("/programs/{program_id}/deduplicate")
def deduplicate_all(
    program_id: int,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    """Run deduplication across every finding in a program."""
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    return deduplicate_program(db, program_id, actor=actor)
