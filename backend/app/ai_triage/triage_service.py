"""Triage service — orchestrates AI triage over a Finding ORM object.

The service selects a provider (mock by default), builds a read-only context
from the finding, invokes the provider, applies the result back onto the
finding, and records an audit entry.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.ai_triage.base import AITriageProvider, FindingContext
from app.ai_triage.mock_provider import MockTriageProvider
from app.models import Finding
from app.schemas.schemas import TriageResult
from app.services.audit import record_audit


class TriageService:
    """Run AI triage against findings."""

    def __init__(self, provider: AITriageProvider | None = None):
        # Default to the mock provider. A real LLM provider can be injected.
        self.provider = provider or MockTriageProvider()

    def build_context(self, finding: Finding) -> FindingContext:
        """Create the read-only context snapshot passed to the provider."""
        asset_value = finding.asset.value if finding.asset else None
        return FindingContext(
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=finding.confidence,
            category=finding.category,
            cwe=finding.cwe,
            owasp=finding.owasp,
            evidence_summary=finding.evidence_summary,
            raw_output=finding.raw_output,
            scanner_name=finding.scanner_name,
            asset_value=asset_value,
            remediation=finding.remediation,
        )

    def triage_finding(self, db: Session, finding: Finding, apply: bool = True) -> TriageResult:
        """Triage a finding and optionally persist the enriched fields."""
        context = self.build_context(finding)
        result = self.provider.triage(context)

        if apply:
            finding.title = result.title
            finding.severity = result.severity.value
            finding.confidence = result.confidence.value
            finding.category = result.category
            finding.cwe = result.cwe
            finding.owasp = result.owasp
            finding.impact = result.business_impact
            finding.remediation = result.remediation
            finding.ai_summary = result.ai_summary
            finding.manual_review_required = result.manual_review_required
            # Triage moves a new finding into the review pipeline; it never
            # auto-confirms.
            if finding.status in ("new", "auto_validating"):
                finding.status = "needs_review"
            db.add(finding)
            record_audit(
                db,
                action="finding.triage",
                target=f"finding:{finding.id}",
                decision="info",
                detail=(
                    f"provider={self.provider.name} severity={result.severity.value} "
                    f"manual_review_required={result.manual_review_required}"
                ),
                commit=False,
            )
            db.commit()
            db.refresh(finding)

        return result
