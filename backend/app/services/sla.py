"""Finding SLA helpers.

The SLA deadline is derived from a finding's severity at creation time using the
configured per-severity windows. A finding is "breached" when it is still open
past its deadline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models import Finding

# Statuses that count as "still open" for SLA purposes.
OPEN_STATUSES = ("new", "auto_validating", "needs_review", "confirmed", "retest", "submitted")


def compute_sla_due_at(severity: str, start: datetime | None = None) -> datetime | None:
    """Return the SLA deadline for a severity, or None when untracked."""
    days = settings.sla_days_for(severity)
    if days <= 0:
        return None
    base = start or datetime.now(timezone.utc)
    return base + timedelta(days=days)


def is_breached(finding: Finding, now: datetime | None = None) -> bool:
    """True when an open finding has passed its SLA deadline."""
    if finding.sla_due_at is None or finding.status not in OPEN_STATUSES:
        return False
    moment = now or datetime.now(timezone.utc)
    due = finding.sla_due_at
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    return moment > due
