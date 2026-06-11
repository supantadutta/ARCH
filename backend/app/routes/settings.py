"""Settings + global kill switch routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import settings as app_settings
from app.database import get_db
from app.schemas.schemas import KillSwitchUpdate
from app.services.audit import record_audit
from app.services.killswitch import is_kill_switch_enabled, set_kill_switch

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def get_settings(db: Session = Depends(get_db)):
    """Return the safety-relevant runtime configuration."""
    return {
        "app_name": app_settings.app_name,
        "dry_run_default": app_settings.dry_run,
        "kill_switch_enabled": is_kill_switch_enabled(db),
        "auth_enabled": app_settings.auth_enabled,
        "allow_private_targets": app_settings.allow_private_targets,
        "scanner_rate_limit_per_sec": app_settings.scanner_rate_limit_per_sec,
        "enable_vulnerable_target": app_settings.enable_vulnerable_target,
        "allowed_scan_types": list(app_settings.allowed_scan_types),
        "forbidden_scan_types": list(app_settings.forbidden_scan_types),
    }


@router.post("/kill-switch")
def update_kill_switch(payload: KillSwitchUpdate, db: Session = Depends(get_db)):
    """Engage or release the global kill switch."""
    set_kill_switch(db, payload.enabled)
    record_audit(
        db,
        action="killswitch.update",
        decision="rejected" if payload.enabled else "allowed",
        detail=f"kill_switch_enabled={payload.enabled}",
    )
    return {"kill_switch_enabled": payload.enabled}
