"""Tests for Markdown report generation."""

from app.models import Asset, Finding
from app.reports.report_generator import generate_report_markdown


def test_report_generation_includes_required_sections(db, program_with_scope):
    asset = Asset(program_id=program_with_scope.id, value="localhost", scheme="http", port=8000)
    db.add(asset)
    db.flush()
    finding = Finding(
        program_id=program_with_scope.id,
        asset_id=asset.id,
        title="Missing security headers",
        description="No CSP header present.",
        severity="low",
        confidence="medium",
        status="confirmed",
        category="misconfiguration",
        cwe="CWE-693",
        owasp="A05:2021 Security Misconfiguration",
        evidence_summary="Response lacked CSP.",
        impact="Limited impact.",
        remediation="Add CSP header.",
        scanner_name="recon",
        manual_review_required=False,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    title, markdown = generate_report_markdown(db, finding)

    assert "Missing security headers" in title
    for section in (
        "## Summary",
        "## Scope",
        "## Affected Asset",
        "## Severity",
        "## Steps to Reproduce",
        "## Impact",
        "## Remediation",
        "## References",
        "## Timeline",
    ):
        assert section in markdown
    # Safe-by-design: reproduction steps must warn against destructive actions.
    assert "destructive" in markdown.lower()


def test_report_flags_manual_review(db, program_with_scope):
    finding = Finding(
        program_id=program_with_scope.id,
        title="Unverified issue",
        severity="high",
        confidence="low",
        status="needs_review",
        manual_review_required=True,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    _, markdown = generate_report_markdown(db, finding)
    assert "Manual review required" in markdown
