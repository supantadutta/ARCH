"""Dashboard / overview statistics routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Finding, Program, ScanJob
from app.schemas.schemas import AssetOut, ScanJobOut
from app.services.killswitch import is_kill_switch_enabled

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

    running_scans = (
        db.query(func.count(ScanJob.id))
        .filter(ScanJob.status.in_(("queued", "running")))
        .scalar()
        or 0
    )
    needs_review = (
        db.query(func.count(Finding.id)).filter(Finding.status == "needs_review").scalar() or 0
    )

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
        "running_scans": running_scans,
        "needs_review_findings": needs_review,
        "kill_switch_enabled": is_kill_switch_enabled(db),
        "recent_scan_jobs": [ScanJobOut.model_validate(j).model_dump() for j in recent_jobs],
        "top_risky_assets": [AssetOut.model_validate(a).model_dump() for a in top_assets],
    }
