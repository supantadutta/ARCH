"""Tests for the AI triage provider interface, structured output and grounding."""

from __future__ import annotations

import pytest

from app.ai_triage import TriageService, available_providers, get_provider
from app.ai_triage.base import FindingContext, enforce_grounding
from app.ai_triage.mock_provider import MockTriageProvider
from app.ai_triage.openai_provider import AITriageError, OpenAITriageProvider
from app.ai_triage.local_provider import LocalLLMTriageProvider
from app.models import Asset, Finding
from app.schemas.schemas import Confidence, Severity, TriageResult


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
        evidence_summary="Response from http://localhost lacked CSP.",
        scanner_name="recon",
    )
    defaults.update(overrides)
    finding = Finding(**defaults)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


# --------------------------------------------------------------------------
# Provider registry (requirement 1)
# --------------------------------------------------------------------------
def test_three_providers_registered():
    assert set(available_providers()) == {"mock", "openai", "local"}
    assert isinstance(get_provider("mock"), MockTriageProvider)
    assert isinstance(get_provider("openai"), OpenAITriageProvider)
    assert isinstance(get_provider("local"), LocalLLMTriageProvider)
    # Unknown -> safe default.
    assert isinstance(get_provider("nonsense"), MockTriageProvider)


# --------------------------------------------------------------------------
# Structured JSON (requirement 2)
# --------------------------------------------------------------------------
def test_structured_json_has_all_required_keys(db, program_with_scope):
    finding = _make_finding(db, program_with_scope)
    result = TriageService(provider=MockTriageProvider()).triage_finding(db, finding, apply=False)
    structured = result.to_structured_json()
    expected = {
        "title", "severity", "confidence", "category", "cwe", "owasp",
        "impact", "remediation", "evidence_used", "report_draft",
        "manual_review_required",
    }
    assert set(structured) == expected
    assert isinstance(structured["evidence_used"], list)
    assert isinstance(structured["manual_review_required"], bool)


def test_mock_evidence_used_is_drawn_from_finding(db, program_with_scope):
    finding = _make_finding(db, program_with_scope)
    result = TriageService(provider=MockTriageProvider()).triage_finding(db, finding, apply=False)
    # The single evidence item must be the finding's own evidence_summary.
    assert result.evidence_used == ["Response from http://localhost lacked CSP."]


# --------------------------------------------------------------------------
# No-invention rule / grounding guard (requirement 3)
# --------------------------------------------------------------------------
def test_grounding_strips_invented_evidence():
    ctx = FindingContext(
        title="Missing header",
        description="No CSP.",
        severity="low",
        confidence="high",
        category="misconfiguration",
        cwe="CWE-693",
        owasp="A05",
        evidence_summary="Response lacked CSP.",
        raw_output=None,
        scanner_name="recon",
        asset_value="localhost",
    )
    # A provider that fabricates evidence (a URL/credential not in the finding).
    bad = TriageResult(
        title="x", severity=Severity.low, confidence=Confidence.high,
        category="misconfiguration", cwe="CWE-693", owasp="A05",
        business_impact="impact", remediation="fix",
        evidence_used=[
            "Response lacked CSP.",                 # grounded -> kept
            "Found admin password admin:hunter2",   # invented -> dropped
            "https://evil.example.com/secret",      # invented -> dropped
        ],
        report_draft="draft", manual_review_required=False, ai_summary="s",
    )
    out = enforce_grounding(bad, ctx)
    assert out.evidence_used == ["Response lacked CSP."]
    # Because invented evidence was present, manual review is forced on.
    assert out.manual_review_required is True


def test_no_evidence_forces_manual_review(db, program_with_scope):
    finding = _make_finding(db, program_with_scope, evidence_summary=None, raw_output=None)
    result = TriageService(provider=MockTriageProvider()).triage_finding(db, finding, apply=False)
    assert result.evidence_used == []
    assert result.manual_review_required is True


# --------------------------------------------------------------------------
# OpenAI provider behaviour without network (safe failure)
# --------------------------------------------------------------------------
def test_openai_provider_requires_api_key(db, program_with_scope):
    ctx = TriageService().build_context(_make_finding(db, program_with_scope))
    provider = OpenAITriageProvider(api_key="")
    with pytest.raises(AITriageError):
        provider.triage(ctx)


def test_openai_provider_parses_and_grounds_mocked_response(db, program_with_scope, monkeypatch):
    finding = _make_finding(db, program_with_scope)
    ctx = TriageService().build_context(finding)
    provider = OpenAITriageProvider(api_key="test-key", model="gpt-x")

    # Simulate the model returning some invented evidence alongside a real one.
    fake = {
        "title": "Missing security headers on localhost",
        "severity": "medium",
        "confidence": "high",
        "category": "misconfiguration",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "impact": "Weakened browser protections.",
        "remediation": "Add CSP and X-Frame-Options headers.",
        "evidence_used": ["Response from http://localhost lacked CSP.", "secret token abc123"],
        "report_draft": "## Report",
        "manual_review_required": False,
    }
    monkeypatch.setattr(provider, "_call", lambda payload: fake)
    result = provider.triage(ctx)
    # Grounded evidence kept, invented dropped, review forced.
    assert "Response from http://localhost lacked CSP." in result.evidence_used
    assert all("secret token" not in e for e in result.evidence_used)
    assert result.manual_review_required is True
