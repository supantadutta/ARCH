"""Audit log routes (read-only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog
from app.schemas.schemas import AuditLogOut

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=200, le=1000),
    action: str | None = None,
    decision: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if decision:
        query = query.filter(AuditLog.decision == decision)
    return query.order_by(AuditLog.created_at.desc()).limit(limit).all()
