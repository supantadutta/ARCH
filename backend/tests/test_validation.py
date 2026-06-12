"""Tests for safe validation-from-evidence."""

from __future__ import annotations

from app.models import Asset, Finding
from app.validation import validate_finding, validate_program
from app.validation.evidence_validator import (
    STATE_INSUFFICIENT,
    STATE_MANUAL,
    STATE_VALIDATED,
)


def _finding(db, program, **over):
    asset = Asset(program_id=program.id, value="localhost", scheme="http")
    db.add(asset)
    db.flush()
    defaults = dict(
        program_id=program.id,
        asset_id=asset.id,
        title="Missing security headers",
        severity="low",
        confidence="high",
        status="new",
        category="misconfiguration",
        evidence_summary="Response lacked CSP.",
        scanner_name="recon",
    )
    defaults.update(over)
    f = Finding(**defaults)
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def test_no_evidence_is_insufficient_and_manual(db, program_with_scope):
    f = _finding(db, program_with_scope, evidence_summary=None, raw_output=None)
    res = validate_finding(db, f)
    assert res.validation_state == STATE_INSUFFICIENT
    assert res.manual_review_required is True
    assert res.evidence_used == []


def test_low_severity_high_confidence_with_evidence_is_validated(db, program_with_scope):
    f = _finding(db, program_with_scope, severity="low", confidence="high")
    res = validate_finding(db, f)
    assert res.validation_state == STATE_VALIDATED
    assert res.manual_review_required is False
    assert "Response lacked CSP." in res.evidence_used


def test_high_severity_always_requires_manual_review(db, program_with_scope):
    f = _finding(db, program_with_scope, severity="critical", confidence="high")
    res = validate_finding(db, f)
    assert res.validation_state == STATE_MANUAL
    assert res.manual_review_required is True


def test_low_confidence_requires_manual_review(db, program_with_scope):
    f = _finding(db, program_with_scope, severity="low", confidence="low")
    res = validate_finding(db, f)
    assert res.validation_state == STATE_MANUAL
    assert res.manual_review_required is True


def test_validation_never_auto_confirms_status(db, program_with_scope):
    f = _finding(db, program_with_scope, severity="low", confidence="high", status="new")
    validate_finding(db, f)
    db.refresh(f)
    # New -> needs_review, never jumps straight to confirmed.
    assert f.status == "needs_review"
    assert f.validation_state == STATE_VALIDATED
    assert f.validated_at is not None


def test_validate_program_summarizes(db, program_with_scope):
    _finding(db, program_with_scope, severity="low", confidence="high")
    _finding(db, program_with_scope, severity="critical", confidence="high")
    _finding(db, program_with_scope, evidence_summary=None, raw_output=None)
    summary = validate_program(db, program_with_scope.id)
    assert summary["scanned"] == 3
    assert summary[STATE_VALIDATED] == 1
    assert summary[STATE_MANUAL] == 1
    assert summary[STATE_INSUFFICIENT] == 1


def test_validate_endpoint_and_access(client, db):
    pid = client.post("/api/v1/programs", json={"name": "P"}).json()["id"]
    fid = client.post(
        f"/api/v1/programs/{pid}/findings",
        json={
            "title": "t", "severity": "low", "confidence": "high",
            "evidence_summary": "concrete evidence here",
        },
    ).json()["id"]
    r = client.post(f"/api/v1/findings/{fid}/validate")
    assert r.status_code == 200
    assert r.json()["validation_state"] == STATE_VALIDATED
