"""Audit logging helper.

Every security-relevant action (scope decisions, scan launches, kill-switch
changes, status transitions) is recorded here to provide an immutable trail.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AuditLog


def record_audit(
    db: Session,
    *,
    action: str,
    actor: str = "system",
    target: str | None = None,
    decision: str = "info",
    detail: str | None = None,
    commit: bool = True,
) -> AuditLog:
    """Persist an audit-log entry.

    Parameters
    ----------
    action: short machine-readable action key (e.g. ``scan.launch``).
    decision: ``allowed`` | ``rejected`` | ``info``.
    """

    entry = AuditLog(
        actor=actor,
        action=action,
        target=target,
        decision=decision,
        detail=detail,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry
