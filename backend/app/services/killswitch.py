"""Global kill switch.

The kill switch is persisted in the ``system_settings`` table so it survives
restarts and is shared across the API and Celery workers. When enabled, no new
scan jobs may be queued or executed.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.config import settings
from app.models import SystemSetting

KILL_SWITCH_KEY = "kill_switch_enabled"


def _get_setting(db: Session, key: str) -> SystemSetting | None:
    return db.query(SystemSetting).filter(SystemSetting.key == key).first()


def is_kill_switch_enabled(db: Session) -> bool:
    """Return True if the global kill switch is currently engaged."""
    row = _get_setting(db, KILL_SWITCH_KEY)
    if row is None:
        # Fall back to the configured default.
        return settings.kill_switch_enabled
    return row.value.lower() in ("1", "true", "yes", "on")


def set_kill_switch(db: Session, enabled: bool) -> bool:
    """Enable or disable the kill switch and persist the new value."""
    row = _get_setting(db, KILL_SWITCH_KEY)
    if row is None:
        row = SystemSetting(
            key=KILL_SWITCH_KEY,
            value="true" if enabled else "false",
            description="Global kill switch — blocks all new scans when true.",
        )
        db.add(row)
    else:
        row.value = "true" if enabled else "false"
    db.commit()
    return enabled
