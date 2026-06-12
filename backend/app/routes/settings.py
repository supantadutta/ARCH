"""Settings + global kill switch routes."""

from __future__ import annotations

import shutil

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import settings as app_settings
from app.database import get_db
from app.scanners.registry import SCANNER_REGISTRY
from app.schemas.schemas import KillSwitchUpdate
from app.services.audit import record_audit
from app.services.killswitch import is_kill_switch_enabled, set_kill_switch

router = APIRouter(prefix="/settings", tags=["settings"])

# Short, human-readable description of each scanner's safe default mode.
_SCANNER_MODES = {
    "recon": "Passive HTTP/HTTPS probing (pure Python, always available)",
    "nuclei": "Non-intrusive templates only (intrusive tags excluded)",
    "zap_baseline": "Baseline passive scan only (no active attacks)",
    "semgrep": "Static analysis of an authorized local source path",
    "gitleaks": "Secret detection on an authorized local repo path",
    "trivy": "Dependency/vuln scan of an authorized local path/image",
}


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
        "scanner_timeout_seconds": app_settings.scanner_timeout_seconds,
        "enable_vulnerable_target": app_settings.enable_vulnerable_target,
        "authorized_scan_paths": list(app_settings.authorized_scan_path_list),
        "allowed_scan_types": list(app_settings.allowed_scan_types),
        "forbidden_scan_types": list(app_settings.forbidden_scan_types),
    }


@router.get("/scanners")
def get_scanner_status():
    """Per-scanner status for the dashboard: enabled, installed and runnable.

    A scanner only executes for real when ``enabled`` AND ``installed`` are both
    true. ``recon`` is pure-Python and always available; everything else is
    opt-in and disabled by default.
    """
    scanners = []
    # Recon is not in the subprocess registry (pure Python) — surface it too.
    scanners.append(
        {
            "name": "recon",
            "enabled": True,
            "installed": True,
            "binary": None,
            "target_kind": "network",
            "default_mode": _SCANNER_MODES["recon"],
            "runnable": True,
        }
    )
    for name, cls in SCANNER_REGISTRY.items():
        if name == "recon":
            continue
        binary = getattr(cls, "binary", None)
        installed = bool(binary) and shutil.which(binary) is not None
        enabled = app_settings.scanner_enabled(name)
        scanners.append(
            {
                "name": name,
                "enabled": enabled,
                "installed": installed,
                "binary": binary,
                "target_kind": getattr(cls, "target_kind", "network"),
                "default_mode": _SCANNER_MODES.get(name, ""),
                "runnable": enabled and installed,
            }
        )
    return {
        "scanners": scanners,
        "timeout_seconds": app_settings.scanner_timeout_seconds,
        "authorized_scan_paths": list(app_settings.authorized_scan_path_list),
        "dry_run_default": app_settings.dry_run,
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
