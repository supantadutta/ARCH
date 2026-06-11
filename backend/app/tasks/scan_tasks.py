"""Celery tasks that execute scan jobs under full policy enforcement.

The task re-checks the kill switch and the scope guard at execution time (not
just at enqueue time), so an operator engaging the kill switch immediately
prevents queued jobs from running.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Asset, Finding, ScanJob
from app.scanners.registry import get_scanner_class
from app.services.audit import record_audit
from app.services.killswitch import is_kill_switch_enabled


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _update_state(task, state: str, meta: dict) -> None:
    """Best-effort Celery progress update (no-op when run eagerly/in tests)."""
    try:
        if task is not None and getattr(task, "request", None) is not None:
            task.update_state(state=state, meta=meta)
    except Exception:  # pragma: no cover - progress reporting is non-critical
        pass


@celery_app.task(name="run_scan_job", bind=True)
def run_scan_job(self, scan_job_id: int) -> dict:
    """Execute a scan job by id. Returns a small status dict.

    The job's ``status`` field is updated through its full lifecycle
    (queued → running → completed/failed/cancelled) and progress is also
    published to Celery's result backend via ``update_state``.
    """
    db = SessionLocal()
    try:
        job: ScanJob | None = db.get(ScanJob, scan_job_id)
        if job is None:
            return {"status": "missing", "scan_job_id": scan_job_id}

        # Hard control: kill switch blocks execution.
        if is_kill_switch_enabled(db):
            job.status = "cancelled"
            job.error_message = "Kill switch engaged — scan not executed."
            job.finished_at = _now()
            record_audit(
                db,
                action="scan.killswitch_block",
                target=job.target,
                decision="rejected",
                detail=f"job {job.id} cancelled by kill switch",
                commit=False,
            )
            db.commit()
            return {"status": "cancelled", "reason": "kill_switch"}

        scanner_cls = get_scanner_class(job.job_type)
        if scanner_cls is None:
            job.status = "failed"
            job.error_message = f"Unsupported job type '{job.job_type}'."
            job.finished_at = _now()
            db.commit()
            return {"status": "failed", "reason": "unsupported_type"}

        # Transition to running and record a dedicated "scan started" event.
        job.status = "running"
        job.started_at = _now()
        job.logs = f"[task] job {job.id} started ({job.job_type}, dry_run={job.dry_run})"
        record_audit(
            db,
            action="scan.started",
            target=job.target,
            decision="info",
            detail=f"job {job.id} {job.job_type} dry_run={job.dry_run}",
            commit=False,
        )
        db.commit()
        # Surface progress to Celery's result backend so clients can poll state.
        _update_state(self, "RUNNING", {"job_id": job.id, "phase": "scanning"})

        scanner = scanner_cls(db, job.program_id)
        result = scanner.run(job.target, dry_run=job.dry_run)

        job.logs = result.logs
        if result.error:
            job.status = "failed"
            job.error_message = result.error
            job.finished_at = _now()
            db.commit()
            return {"status": "failed", "error": result.error}

        # Persist discovered assets (recon).
        _update_state(self, "RUNNING", {"job_id": job.id, "phase": "persisting"})
        for asset_data in result.assets:
            _upsert_asset(db, job.program_id, asset_data)

        # Persist normalized findings.
        created = 0
        for sf in result.findings:
            db.add(
                Finding(
                    program_id=job.program_id,
                    title=sf.title,
                    description=sf.description,
                    severity=sf.severity,
                    confidence=sf.confidence,
                    category=sf.category,
                    cwe=sf.cwe,
                    owasp=sf.owasp,
                    evidence_summary=sf.evidence_summary,
                    raw_output=sf.raw_output,
                    scanner_name=sf.scanner_name or job.job_type,
                    status="new",
                    manual_review_required=sf.manual_review_required,
                )
            )
            created += 1

        job.status = "completed"
        job.finished_at = _now()
        record_audit(
            db,
            action="scan.completed",
            target=job.target,
            decision="info",
            detail=f"job {job.id} {job.job_type} findings={created} assets={len(result.assets)}",
            commit=False,
        )
        db.commit()
        return {"status": "completed", "findings": created, "assets": len(result.assets)}
    except Exception as exc:  # pragma: no cover - defensive
        db.rollback()
        job = db.get(ScanJob, scan_job_id)
        if job:
            job.status = "failed"
            job.error_message = str(exc)
            job.finished_at = _now()
            db.commit()
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()


def _upsert_asset(db, program_id: int, data: dict) -> None:
    """Insert or update an asset discovered during recon."""
    existing = (
        db.query(Asset)
        .filter(
            Asset.program_id == program_id,
            Asset.value == data["value"],
            Asset.scheme == data.get("scheme"),
        )
        .first()
    )
    if existing:
        existing.ip_address = data.get("ip_address") or existing.ip_address
        existing.technologies = data.get("technologies") or existing.technologies
        existing.last_seen = _now()
        existing.status = data.get("status", existing.status)
    else:
        db.add(
            Asset(
                program_id=program_id,
                asset_type=data.get("asset_type", "web"),
                value=data["value"],
                ip_address=data.get("ip_address"),
                port=data.get("port"),
                scheme=data.get("scheme"),
                status=data.get("status", "active"),
                technologies=data.get("technologies"),
                last_seen=_now(),
            )
        )
