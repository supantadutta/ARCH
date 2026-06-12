"""Dashboard / overview statistics routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Finding, Program, ScanJob
from app.schemas.schemas import AssetOut, ScanJobOut
from app.services.killswitch import is_kill_switch_enabled
from app.services.sla import OPEN_STATUSES, is_breached

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    """Aggregate widgets for the dashboard landing page."""
    total_programs = db.query(func.count(Program.id)).scalar() or 0
    total_assets = db.query(func.count(Asset.id)).scalar() or 0

    open_statuses = ("new", "auto_validating", "needs_review", "confirmed")
    severity_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.status.in_(open_statuses))
        .group_by(Finding.severity)
        .all()
    )
    open_by_severity = {sev: 0 for sev in ("info", "low", "medium", "high", "critical")}
    for sev, count in severity_rows:
        open_by_severity[sev] = count

    # Findings grouped by status (for the status chart).
    status_rows = (
        db.query(Finding.status, func.count(Finding.id)).group_by(Finding.status).all()
    )
    findings_by_status = {status: count for status, count in status_rows}

    running_scans = (
        db.query(func.count(ScanJob.id))
        .filter(ScanJob.status.in_(("queued", "running")))
        .scalar()
        or 0
    )
    needs_review = (
        db.query(func.count(Finding.id)).filter(Finding.status == "needs_review").scalar() or 0
    )

    # SLA breaches among open findings.
    open_findings = (
        db.query(Finding)
        .filter(Finding.status.in_(OPEN_STATUSES), Finding.sla_due_at.isnot(None))
        .all()
    )
    sla_breached = sum(1 for f in open_findings if is_breached(f))

    recent_jobs = (
        db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(10).all()
    )
    top_assets = (
        db.query(Asset).order_by(Asset.risk_score.desc()).limit(10).all()
    )

    return {
        "total_programs": total_programs,
        "total_assets": total_assets,
        "open_findings_by_severity": open_by_severity,
        "findings_by_status": findings_by_status,
        "running_scans": running_scans,
        "needs_review_findings": needs_review,
        "sla_breached_findings": sla_breached,
        "kill_switch_enabled": is_kill_switch_enabled(db),
        "recent_scan_jobs": [ScanJobOut.model_validate(j).model_dump() for j in recent_jobs],
        "top_risky_assets": [AssetOut.model_validate(a).model_dump() for a in top_assets],
    }
