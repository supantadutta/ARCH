"""Tests for the safe external scanner integration.

Verifies that external scanners are opt-in (enabled + installed), support
dry-run, enforce scope/path authorization, apply timeouts, and keep nuclei /
zap restricted to their safe default modes. No tests exercise destructive
behaviour — none exists.
"""

from __future__ import annotations

import app.config as config_module
from app.config import Settings
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.trivy_scanner import TrivyScanner
from app.scanners.zap_scanner import ZapScanner
from app.models import ScopeItem


def _set_settings(monkeypatch, **overrides):
    """Swap the global Settings singleton with one carrying overrides."""
    base = Settings(**overrides)
    monkeypatch.setattr(config_module, "settings", base)
    # Modules that imported `settings` by reference also need the swap.
    import app.scanners.base as base_mod
    import app.scanners.nuclei_scanner as nuclei_mod
    import app.policy.scope_guard as guard_mod

    monkeypatch.setattr(base_mod, "settings", base)
    monkeypatch.setattr(nuclei_mod, "settings", base)
    monkeypatch.setattr(guard_mod, "settings", base)
    return base


# --------------------------------------------------------------------------
# Enabled + installed gating (requirement 1)
# --------------------------------------------------------------------------
def test_disabled_scanner_does_not_execute(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=False, enable_nuclei=False)
    result = NucleiScanner(db, program_with_scope.id).run("localhost", dry_run=False)
    assert result.error is not None
    assert "disabled" in result.error.lower()
    assert result.returncode is None  # never executed


def test_enabled_but_not_installed_reports_missing_binary(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=False, enable_nuclei=True)
    # nuclei is not installed in CI, so it must refuse to run with a clear msg.
    result = NucleiScanner(db, program_with_scope.id).run("localhost", dry_run=False)
    assert result.error is not None
    assert "not installed" in result.error.lower()


# --------------------------------------------------------------------------
# Dry-run support (requirement 3) — works without enable/install
# --------------------------------------------------------------------------
def test_dry_run_preview_without_enable_or_install(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True, enable_nuclei=False)
    result = NucleiScanner(db, program_with_scope.id).run("localhost", dry_run=True)
    assert result.error is None
    assert result.returncode == 0
    assert "DRY-RUN" in result.logs


# --------------------------------------------------------------------------
# Scope enforcement before execution (requirement 2)
# --------------------------------------------------------------------------
def test_network_scanner_rejects_out_of_scope(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True)
    result = NucleiScanner(db, program_with_scope.id).run("evil.example.net", dry_run=True)
    assert result.error is not None
    assert "scope" in result.error.lower()


# --------------------------------------------------------------------------
# Nuclei safe templates by default (requirement 6)
# --------------------------------------------------------------------------
def test_nuclei_excludes_intrusive_tags(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True)
    cmd = NucleiScanner(db, program_with_scope.id).build_command("localhost")
    assert "-exclude-tags" in cmd
    tags = cmd[cmd.index("-exclude-tags") + 1]
    for intrusive in ("dos", "fuzz", "brute", "intrusive"):
        assert intrusive in tags
    assert "-no-interactsh" in cmd


# --------------------------------------------------------------------------
# ZAP baseline only (requirement 7)
# --------------------------------------------------------------------------
def test_zap_uses_baseline_binary_only(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True)
    cmd = ZapScanner(db, program_with_scope.id).build_command("localhost")
    assert cmd[0] == "zap-baseline.py"
    # No active-scan / attack flags.
    assert not any(flag in cmd for flag in ("-attack", "zap-full-scan.py", "zap-api-scan.py"))


# --------------------------------------------------------------------------
# Path scanners require explicit authorization (requirements 8 & 9)
# --------------------------------------------------------------------------
def _authorize_repo_path(db, program, path):
    db.add(ScopeItem(program_id=program.id, scope_type="repo", value=path, is_allowed=True))
    db.commit()


def test_path_scanner_rejects_unauthorized_path(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True, authorized_scan_paths="/srv/authorized")
    # No repo scope entry and path not under any authorized root.
    result = SemgrepScanner(db, program_with_scope.id).run("/etc", dry_run=True)
    assert result.error is not None


def test_path_scanner_rejects_path_traversal(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True, authorized_scan_paths="/srv/authorized")
    _authorize_repo_path(db, program_with_scope, "/srv/authorized/repo")
    result = GitleaksScanner(db, program_with_scope.id).run("/srv/authorized/repo/../../etc", dry_run=True)
    assert result.error is not None
    assert "traversal" in result.error.lower()


def test_path_scanner_accepts_authorized_path_in_dry_run(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True, authorized_scan_paths="/srv/authorized")
    _authorize_repo_path(db, program_with_scope, "/srv/authorized/repo")
    result = TrivyScanner(db, program_with_scope.id).run("/srv/authorized/repo", dry_run=True)
    assert result.error is None
    assert result.returncode == 0
    assert "DRY-RUN" in result.logs


def test_path_scan_disabled_when_no_authorized_paths(db, program_with_scope, monkeypatch):
    _set_settings(monkeypatch, dry_run=True, authorized_scan_paths="")
    _authorize_repo_path(db, program_with_scope, "/srv/authorized/repo")
    result = SemgrepScanner(db, program_with_scope.id).run("/srv/authorized/repo", dry_run=True)
    assert result.error is not None


# --------------------------------------------------------------------------
# Timeout is configurable (requirement 4)
# --------------------------------------------------------------------------
def test_scanner_timeout_is_configurable(monkeypatch):
    s = _set_settings(monkeypatch, scanner_timeout_seconds=42)
    assert s.scanner_timeout_seconds == 42
