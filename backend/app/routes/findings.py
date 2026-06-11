"""Findings routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import Evidence, Finding, Program
from app.schemas.schemas import (
    EvidenceOut,
    FindingCreate,
    FindingOut,
    FindingUpdate,
)
from app.services.audit import record_audit

router = APIRouter(tags=["findings"])


@router.get("/programs/{program_id}/findings", response_model=list[FindingOut])
def list_findings(
    program_id: int,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(Finding).filter(Finding.program_id == program_id)
    if status:
        query = query.filter(Finding.status == status)
    if severity:
        query = query.filter(Finding.severity == severity)
    return query.order_by(Finding.created_at.desc()).all()


@router.post("/programs/{program_id}/findings", response_model=FindingOut, status_code=201)
def create_finding(
    program_id: int,
    payload: FindingCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    finding = Finding(
        program_id=program_id,
        status="new",
        **payload.model_dump(),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    record_audit(
        db,
        action="finding.create",
        actor=actor,
        target=f"finding:{finding.id}",
        detail=finding.title,
    )
    return finding


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = payload.model_dump(exclude_unset=True)
    previous_status = finding.status
    # Enums -> their string values.
    for key, value in data.items():
        setattr(finding, key, value.value if hasattr(value, "value") else value)
    db.commit()
    db.refresh(finding)

    # Emit a dedicated audit event when the status transitions, capturing the
    # before/after so the lifecycle is fully traceable.
    if "status" in data and finding.status != previous_status:
        record_audit(
            db,
            action="finding.status_changed",
            actor=actor,
            target=f"finding:{finding_id}",
            detail=f"{previous_status} -> {finding.status}",
            commit=False,
        )
    record_audit(
        db,
        action="finding.update",
        actor=actor,
        target=f"finding:{finding_id}",
        detail=f"status={finding.status} severity={finding.severity}",
    )
    return finding


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(finding_id: int, db: Session = Depends(get_db)):
    return db.query(Evidence).filter(Evidence.finding_id == finding_id).all()
