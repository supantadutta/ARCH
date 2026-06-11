"""Scan job routes — recon & scanner jobs.

Launching a scan is the most safety-critical operation. This route enforces, in
order: kill switch, scan-type allowlist, and scope guard — *before* a job is
ever queued. The Celery task re-checks these at execution time as well.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.config import settings
from app.database import get_db
from app.models import Program, ScanJob
from app.policy.scope_guard import ScopeError, validate_scan_request
from app.schemas.schemas import ScanJobCreate, ScanJobOut
from app.services.audit import record_audit
from app.services.killswitch import is_kill_switch_enabled
from app.tasks.scan_tasks import run_scan_job

router = APIRouter(prefix="/programs/{program_id}/scans", tags=["scans"])


@router.get("", response_model=list[ScanJobOut])
def list_scans(program_id: int, db: Session = Depends(get_db)):
    return (
        db.query(ScanJob)
        .filter(ScanJob.program_id == program_id)
        .order_by(ScanJob.created_at.desc())
        .all()
    )


@router.post("", response_model=ScanJobOut, status_code=201)
def launch_scan(
    program_id: int,
    payload: ScanJobCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")

    # 1. Kill switch — refuse to queue anything while engaged.
    if is_kill_switch_enabled(db):
        record_audit(
            db,
            action="scan.rejected",
            actor=actor,
            target=payload.target,
            decision="rejected",
            detail="Kill switch engaged.",
        )
        raise HTTPException(status_code=423, detail="Global kill switch is engaged; scanning disabled.")

    # 2. Scope + scan-type validation (hard control before queueing).
    try:
        decision = validate_scan_request(db, program_id, payload.target, payload.job_type.value)
    except ScopeError as exc:
        record_audit(
            db,
            action="scan.rejected",
            actor=actor,
            target=payload.target,
            decision="rejected",
            detail=exc.decision.reason,
        )
        raise HTTPException(status_code=403, detail=exc.decision.reason) from exc

    dry_run = settings.dry_run if payload.dry_run is None else payload.dry_run

    job = ScanJob(
        program_id=program_id,
        job_type=payload.job_type.value,
        target=decision.normalized_target,
        status="queued",
        dry_run=dry_run,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    record_audit(
        db,
        action="scan.launch",
        actor=actor,
        target=decision.normalized_target,
        decision="allowed",
        detail=f"job:{job.id} type={job.job_type} dry_run={dry_run}",
    )

    # Queue the job. If the broker is unavailable the job stays "queued".
    try:
        run_scan_job.delay(job.id)
    except Exception as exc:  # pragma: no cover - broker connectivity
        job.error_message = f"Failed to enqueue: {exc}"
        db.commit()

    return job


@router.get("/{job_id}", response_model=ScanJobOut)
def get_scan(program_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJob, job_id)
    if not job or job.program_id != program_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("/{job_id}/cancel", response_model=ScanJobOut)
def cancel_scan(program_id: int, job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJob, job_id)
    if not job or job.program_id != program_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status in ("queued", "running"):
        job.status = "cancelled"
        db.commit()
        db.refresh(job)
        record_audit(db, action="scan.cancel", target=job.target, detail=f"job:{job_id}")
    return job
