"""Tests for the major safety controls.

Covers authorization, scope enforcement, the global kill switch, dry-run
behaviour, the scanner command allowlist, and audit logging — i.e. the hard
controls that keep the platform authorized-only and non-destructive.
"""

from __future__ import annotations

import pytest

from app.models import AuditLog, Program, ScopeItem
from app.scanners.base import BaseScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.recon_scanner import ReconScanner
from app.services.killswitch import set_kill_switch


# --------------------------------------------------------------------------
# Authorization
# --------------------------------------------------------------------------
def test_request_without_api_key_is_rejected(client):
    client.headers.pop("X-API-Key", None)
    resp = client.get("/api/v1/programs")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_request_with_bad_api_key_is_rejected(client):
    client.headers.update({"X-API-Key": "wrong-key"})
    resp = client.get("/api/v1/programs")
    assert resp.status_code == 401


def test_request_with_valid_api_key_succeeds(client):
    resp = client.get("/api/v1/programs")
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# Scope enforcement on the scan endpoint
# --------------------------------------------------------------------------
def _make_program_with_localhost(client) -> int:
    pid = client.post("/api/v1/programs", json={"name": "Authorized"}).json()["id"]
    client.post(
        f"/api/v1/programs/{pid}/scope",
        json={"scope_type": "domain", "value": "localhost", "is_allowed": True},
    )
    return pid


def test_out_of_scope_scan_is_rejected_with_403(client):
    pid = _make_program_with_localhost(client)
    resp = client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "recon", "target": "evil.example.com", "dry_run": True},
    )
    assert resp.status_code == 403
    assert "scope" in resp.json()["detail"].lower()


def test_forbidden_scan_type_is_rejected(client):
    pid = _make_program_with_localhost(client)
    resp = client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "dos", "target": "localhost", "dry_run": True},
    )
    # "dos" is not a valid JobType enum -> validation error (422).
    assert resp.status_code == 422


def test_in_scope_scan_is_accepted(client):
    pid = _make_program_with_localhost(client)
    resp = client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "recon", "target": "localhost", "dry_run": True},
    )
    assert resp.status_code == 201
    assert resp.json()["status"] in ("queued", "running", "completed")


# --------------------------------------------------------------------------
# Global kill switch
# --------------------------------------------------------------------------
def test_kill_switch_blocks_scan_launch(client):
    pid = _make_program_with_localhost(client)
    client.post("/api/v1/settings/kill-switch", json={"enabled": True})
    resp = client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "recon", "target": "localhost", "dry_run": True},
    )
    assert resp.status_code == 423
    # Release it again and confirm scans resume.
    client.post("/api/v1/settings/kill-switch", json={"enabled": False})
    resp2 = client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "recon", "target": "localhost", "dry_run": True},
    )
    assert resp2.status_code == 201


def test_kill_switch_blocks_task_execution(db, engine, program_with_scope, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    from app.models import ScanJob
    from app.tasks import scan_tasks

    # Point the task's session factory at the in-memory test engine.
    monkeypatch.setattr(
        scan_tasks, "SessionLocal", sessionmaker(bind=engine, autoflush=False, autocommit=False)
    )

    set_kill_switch(db, True)
    job = ScanJob(
        program_id=program_with_scope.id,
        job_type="recon",
        target="localhost",
        status="queued",
        dry_run=True,
    )
    db.add(job)
    db.commit()
    job_id = job.id

    # Execute the task body; the kill switch must cancel it before scanning.
    result = scan_tasks.run_scan_job.run(job_id)
    assert result["status"] == "cancelled"

    db.expire_all()
    assert db.get(ScanJob, job_id).status == "cancelled"


# --------------------------------------------------------------------------
# Dry-run behaviour
# --------------------------------------------------------------------------
def test_recon_dry_run_makes_no_network_calls(db, program_with_scope, monkeypatch):
    import app.scanners.recon_scanner as rs

    def _boom(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("Dry-run must not perform any network request!")

    monkeypatch.setattr(rs.requests, "get", _boom)
    monkeypatch.setattr(rs.socket, "gethostbyname", _boom)

    result = ReconScanner(db, program_with_scope.id).run("localhost", dry_run=True)
    assert result.error is None
    assert "DRY-RUN" in result.logs
    assert result.assets == []


def test_subprocess_scanner_dry_run_does_not_execute(db, program_with_scope):
    # nuclei is not installed in CI; dry-run must still succeed without running.
    result = NucleiScanner(db, program_with_scope.id).run("localhost", dry_run=True)
    assert result.error is None
    assert result.returncode == 0
    assert "DRY-RUN" in result.logs


# --------------------------------------------------------------------------
# Scanner command allowlist (defence in depth)
# --------------------------------------------------------------------------
def test_command_allowlist_rejects_wrong_binary(db, program_with_scope):
    scanner = NucleiScanner(db, program_with_scope.id)
    with pytest.raises(ValueError):
        scanner._assert_command_is_safe(["rm", "-rf", "/"])


def test_command_allowlist_rejects_shell_metacharacters(db, program_with_scope):
    scanner = NucleiScanner(db, program_with_scope.id)
    with pytest.raises(ValueError):
        scanner._assert_command_is_safe(["nuclei", "-target", "localhost; rm -rf /"])


# --------------------------------------------------------------------------
# Audit logging
# --------------------------------------------------------------------------
def test_audit_log_records_program_and_scope_and_scan(client, db):
    pid = _make_program_with_localhost(client)
    client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "recon", "target": "localhost", "dry_run": True},
    )
    actions = {row.action for row in db.query(AuditLog).all()}
    assert "program.create" in actions
    assert "scope.add" in actions
    assert "scan.launch" in actions


def test_audit_log_records_finding_status_change(client, db):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    fid = client.post(
        f"/api/v1/programs/{pid}/findings",
        json={"title": "T", "severity": "low", "confidence": "low"},
    ).json()["id"]
    client.patch(f"/api/v1/findings/{fid}", json={"status": "confirmed"})

    actions = [row.action for row in db.query(AuditLog).all()]
    assert "finding.create" in actions
    assert "finding.status_changed" in actions


def test_out_of_scope_attempt_is_audited_as_rejected(client, db):
    pid = _make_program_with_localhost(client)
    client.post(
        f"/api/v1/programs/{pid}/scans",
        json={"job_type": "recon", "target": "evil.example.com", "dry_run": True},
    )
    rejected = db.query(AuditLog).filter(AuditLog.decision == "rejected").all()
    assert any(r.action == "scan.rejected" for r in rejected)
