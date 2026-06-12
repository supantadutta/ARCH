"""Validation-from-evidence routes (safe, passive)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import (
    ROLE_RESEARCHER,
    ROLE_TRIAGER,
    Principal,
    ensure_program_access,
    require_role,
)
from app.database import get_db
from app.models import Finding, Program
from app.schemas.schemas import FindingOut
from app.validation import validate_finding, validate_program

router = APIRouter(tags=["validation"])


@router.post("/findings/{finding_id}/validate", response_model=FindingOut)
def validate_one(
    finding_id: int,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_TRIAGER, ROLE_RESEARCHER)),
):
    """Validate a finding from its existing evidence only (no re-scanning)."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    validate_finding(db, finding, actor=actor.email)
    return finding


@router.get("/findings/{finding_id}/validation")
def validation_preview(
    finding_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(ROLE_TRIAGER, ROLE_RESEARCHER)),
):
    """Preview the validation outcome without persisting it."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Run on a throwaway flag set: compute, then roll back the mutation.
    from app.validation.evidence_validator import _collect_evidence  # local import

    evidence = _collect_evidence(db, finding)
    db.rollback()
    return {
        "finding_id": finding_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence_items": len(evidence),
        "evidence_used": evidence,
        "would_require_manual_review": (
            not evidence or finding.severity in ("high", "critical") or finding.confidence != "high"
        ),
    }


@router.post("/programs/{program_id}/validate")
def validate_all(
    program_id: int,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_TRIAGER, ROLE_RESEARCHER)),
    __: Principal = Depends(ensure_program_access),
):
    """Validate every (non-duplicate) finding in a program from evidence."""
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    return validate_program(db, program_id, actor=actor.email)
