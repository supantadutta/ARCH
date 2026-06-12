"""Retest workflow routes.

A retest is requested when a finding is believed resolved. The actual retest
re-runs the same passive checks (still scope-gated). Confirming a retest outcome
is a manual, role-gated action — the platform never auto-confirms resolution of
a risky finding.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import (
    ROLE_RESEARCHER,
    ROLE_TRIAGER,
    Principal,
    get_principal,
    require_role,
)
from app.database import get_db
from app.models import Finding, RetestTask
from app.schemas.schemas import RetestTaskOut
from app.services.audit import record_audit
from app.services.notifications import notify

router = APIRouter(tags=["retests"])


def _access(db: Session, principal: Principal, finding: Finding) -> None:
    from app.auth import user_can_access_program

    if not user_can_access_program(db, principal, finding.program_id):
        raise HTTPException(status_code=403, detail="You are not assigned to this program.")


@router.post("/findings/{finding_id}/retest", response_model=RetestTaskOut, status_code=201)
def request_retest(
    finding_id: int,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_TRIAGER, ROLE_RESEARCHER)),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _access(db, actor, finding)
    task = RetestTask(finding_id=finding_id, status="pending")
    finding.status = "retest"
    db.add(task)
    db.commit()
    db.refresh(task)
    record_audit(
        db, action="finding.retest_request", actor=actor.email, target=f"finding:{finding_id}",
        commit=False,
    )
    notify(db, event="finding.retest_requested", message=f"Retest requested for finding #{finding_id}",
           meta={"finding_id": finding_id})
    db.commit()
    db.refresh(task)
    return task


@router.get("/findings/{finding_id}/retests", response_model=list[RetestTaskOut])
def list_retests(
    finding_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _access(db, principal, finding)
    return db.query(RetestTask).filter(RetestTask.finding_id == finding_id).all()


@router.post("/retests/{task_id}/complete", response_model=RetestTaskOut)
def complete_retest(
    task_id: int,
    resolved: bool,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_TRIAGER, ROLE_RESEARCHER)),
):
    """Record a manual retest outcome. Resolution requires a human decision."""
    task = db.get(RetestTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Retest task not found")
    finding = db.get(Finding, task.finding_id)
    if finding:
        _access(db, actor, finding)
    task.status = "completed"
    task.result = "resolved" if resolved else "still_vulnerable"
    task.completed_at = datetime.now(timezone.utc)
    if finding:
        finding.status = "resolved" if resolved else "confirmed"
    db.commit()
    db.refresh(task)
    record_audit(
        db, action="finding.retest_complete", actor=actor.email,
        target=f"finding:{task.finding_id}", detail=task.result,
    )
    return task
