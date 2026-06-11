"""Retest task routes.

A retest is requested when a finding is believed resolved. The actual retest
re-runs the same passive checks (still scope-gated); for the MVP this records
the task and transitions the finding into the ``retest`` state.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, RetestTask
from app.schemas.schemas import RetestTaskOut
from app.services.audit import record_audit

router = APIRouter(tags=["retests"])


@router.post("/findings/{finding_id}/retest", response_model=RetestTaskOut, status_code=201)
def request_retest(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    task = RetestTask(finding_id=finding_id, status="pending")
    finding.status = "retest"
    db.add(task)
    db.commit()
    db.refresh(task)
    record_audit(db, action="finding.retest_request", target=f"finding:{finding_id}")
    return task


@router.get("/findings/{finding_id}/retests", response_model=list[RetestTaskOut])
def list_retests(finding_id: int, db: Session = Depends(get_db)):
    return db.query(RetestTask).filter(RetestTask.finding_id == finding_id).all()


@router.post("/retests/{task_id}/complete", response_model=RetestTaskOut)
def complete_retest(task_id: int, resolved: bool, db: Session = Depends(get_db)):
    task = db.get(RetestTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Retest task not found")
    task.status = "completed"
    task.result = "resolved" if resolved else "still_vulnerable"
    task.completed_at = datetime.now(timezone.utc)
    finding = db.get(Finding, task.finding_id)
    if finding:
        finding.status = "resolved" if resolved else "confirmed"
    db.commit()
    db.refresh(task)
    record_audit(
        db,
        action="finding.retest_complete",
        target=f"finding:{task.finding_id}",
        detail=task.result,
    )
    return task
