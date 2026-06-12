"""Findings routes — with pagination, search, RBAC, SLA and per-program access."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth import (
    ROLE_RESEARCHER,
    ROLE_TRIAGER,
    Principal,
    ensure_program_access,
    get_principal,
    require_role,
)
from app.database import get_db
from app.models import Evidence, Finding, Program
from app.schemas.schemas import (
    EvidenceOut,
    FindingCreate,
    FindingOut,
    FindingUpdate,
    Page,
)
from app.services.audit import record_audit
from app.services.notifications import notify
from app.services.sla import compute_sla_due_at, is_breached

router = APIRouter(tags=["findings"])


@router.get("/programs/{program_id}/findings", response_model=Page)
def list_findings(
    program_id: int,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    q: str | None = Query(default=None, description="Search title/description/category"),
    breached: bool | None = Query(default=None, description="Filter by SLA breach"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    query = db.query(Finding).filter(Finding.program_id == program_id)
    if status:
        query = query.filter(Finding.status == status)
    if severity:
        query = query.filter(Finding.severity == severity)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Finding.title.ilike(like),
                Finding.description.ilike(like),
                Finding.category.ilike(like),
            )
        )
    total = query.count()
    rows = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
    items = [FindingOut.model_validate(r) for r in rows]
    if breached is not None:
        items = [it for it, r in zip(items, rows) if is_breached(r) == breached]
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/programs/{program_id}/findings.csv")
def export_findings_csv(
    program_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    """Export all findings for a program as CSV."""
    rows = (
        db.query(Finding)
        .filter(Finding.program_id == program_id)
        .order_by(Finding.id)
        .all()
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id", "title", "severity", "confidence", "status", "category", "cwe",
            "owasp", "scanner_name", "manual_review_required", "sla_due_at",
            "sla_breached", "duplicate_of", "created_at",
        ]
    )
    for f in rows:
        writer.writerow(
            [
                f.id, f.title, f.severity, f.confidence, f.status, f.category or "",
                f.cwe or "", f.owasp or "", f.scanner_name or "", f.manual_review_required,
                f.sla_due_at.isoformat() if f.sla_due_at else "", is_breached(f),
                f.duplicate_of or "", f.created_at.isoformat() if f.created_at else "",
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="program_{program_id}_findings.csv"'},
    )


@router.post("/programs/{program_id}/findings", response_model=FindingOut, status_code=201)
def create_finding(
    program_id: int,
    payload: FindingCreate,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_RESEARCHER, ROLE_TRIAGER)),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    finding = Finding(
        program_id=program_id,
        status="new",
        **payload.model_dump(),
    )
    # SLA deadline derived from severity at creation.
    finding.sla_due_at = compute_sla_due_at(finding.severity)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    record_audit(
        db, action="finding.create", actor=actor.email,
        target=f"finding:{finding.id}", detail=finding.title, commit=False,
    )
    notify(
        db, event="finding.created",
        message=f"New {finding.severity} finding: {finding.title}",
        meta={"finding_id": finding.id, "program_id": program_id},
    )
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _assert_finding_access(db, principal, finding)
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_TRIAGER, ROLE_RESEARCHER)),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _assert_finding_access(db, actor, finding)
    data = payload.model_dump(exclude_unset=True)
    previous_status = finding.status
    previous_severity = finding.severity
    for key, value in data.items():
        setattr(finding, key, value.value if hasattr(value, "value") else value)
    # If severity changed, recompute the SLA deadline.
    if "severity" in data and finding.severity != previous_severity:
        finding.sla_due_at = compute_sla_due_at(finding.severity, start=finding.created_at)
    db.commit()
    db.refresh(finding)

    if "status" in data and finding.status != previous_status:
        record_audit(
            db, action="finding.status_changed", actor=actor.email,
            target=f"finding:{finding_id}", detail=f"{previous_status} -> {finding.status}",
            commit=False,
        )
    record_audit(
        db, action="finding.update", actor=actor.email, target=f"finding:{finding_id}",
        detail=f"status={finding.status} severity={finding.severity}",
    )
    return finding


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(
    finding_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _assert_finding_access(db, principal, finding)
    return db.query(Evidence).filter(Evidence.finding_id == finding_id).all()


def _assert_finding_access(db: Session, principal: Principal, finding: Finding) -> None:
    """Per-program access: admins/API key see all; others must be members."""
    from app.auth import user_can_access_program

    if not user_can_access_program(db, principal, finding.program_id):
        raise HTTPException(status_code=403, detail="You are not assigned to this program.")
