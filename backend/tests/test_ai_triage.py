"""Tests for the AI triage mock provider."""

from app.ai_triage import TriageService
from app.ai_triage.mock_provider import MockTriageProvider
from app.models import Asset, Finding


def _make_finding(db, program, **overrides):
    asset = Asset(program_id=program.id, value="localhost", scheme="http")
    db.add(asset)
    db.flush()
    defaults = dict(
        program_id=program.id,
        asset_id=asset.id,
        title="Missing security headers",
        description="No CSP header present.",
        severity="low",
        confidence="medium",
        status="new",
        category="misconfiguration",
        evidence_summary="Response lacked CSP.",
        scanner_name="recon",
    )
    defaults.update(overrides)
    finding = Finding(**defaults)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def test_mock_triage_returns_structured_result(db, program_with_scope):
    finding = _make_finding(db, program_with_scope)
    service = TriageService(provider=MockTriageProvider())
    result = service.triage_finding(db, finding, apply=False)

    assert result.title
    assert result.severity.value in ("info", "low", "medium", "high", "critical")
    assert result.cwe
    assert result.owasp
    assert result.report_draft
    assert isinstance(result.manual_review_required, bool)


def test_mock_triage_does_not_invent_evidence(db, program_with_scope):
    # No evidence -> must require manual review and must not fabricate evidence.
    finding = _make_finding(db, program_with_scope, evidence_summary=None, raw_output=None)
    service = TriageService(provider=MockTriageProvider())
    result = service.triage_finding(db, finding, apply=False)

    assert result.manual_review_required is True
    assert "manual review required" in result.report_draft.lower()


def test_high_severity_forces_manual_review(db, program_with_scope):
    finding = _make_finding(db, program_with_scope, severity="critical", confidence="high")
    service = TriageService(provider=MockTriageProvider())
    result = service.triage_finding(db, finding, apply=False)
    assert result.manual_review_required is True


def test_triage_apply_persists_and_moves_to_needs_review(db, program_with_scope):
    finding = _make_finding(db, program_with_scope)
    service = TriageService(provider=MockTriageProvider())
    service.triage_finding(db, finding, apply=True)
    db.refresh(finding)
    assert finding.status == "needs_review"
    assert finding.ai_summary is not None
