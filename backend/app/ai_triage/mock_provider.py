"""Deterministic mock AI triage provider.

This provider produces a plausible, structured triage result **purely from the
data already present** in the finding. It performs no network calls and invents
no new evidence — it normalizes severity, maps categories to CWE/OWASP using a
small lookup table, and composes a report draft from existing fields.

It exists so the platform is fully runnable without any external LLM, and so the
"AI must not invent evidence" guarantee is easy to audit.
"""

from __future__ import annotations

from app.ai_triage.base import AITriageProvider, FindingContext
from app.schemas.schemas import TriageResult

# Small, conservative category -> (CWE, OWASP) lookup. Used only when the
# finding does not already carry these values.
_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "secret": ("CWE-798", "A07:2021 Identification and Authentication Failures"),
    "sast": ("CWE-710", "A06:2021 Vulnerable and Outdated Components"),
    "dependency": ("CWE-1104", "A06:2021 Vulnerable and Outdated Components"),
    "zap-passive": ("CWE-693", "A05:2021 Security Misconfiguration"),
    "nuclei-template": ("CWE-1035", "A06:2021 Vulnerable and Outdated Components"),
    "misconfiguration": ("CWE-16", "A05:2021 Security Misconfiguration"),
}

_VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
_VALID_CONFIDENCE = ("low", "medium", "high")

# Categories / severities that always require a human before any action.
_HIGH_RISK_SEVERITY = ("high", "critical")


class MockTriageProvider(AITriageProvider):
    name = "mock"

    def triage(self, context: FindingContext) -> TriageResult:
        # Never invent: start from what the finding already states.
        severity = context.severity if context.severity in _VALID_SEVERITY else "info"
        confidence = context.confidence if context.confidence in _VALID_CONFIDENCE else "low"

        category = context.category or "misconfiguration"
        cwe, owasp = self._resolve_taxonomy(context, category)

        improved_title = self._improve_title(context)
        business_impact = self._impact_from_severity(severity, context)
        remediation = self._remediation(context, category)

        # Any high/critical severity, or any finding lacking confirming evidence,
        # must be flagged for manual review — the AI never auto-confirms.
        has_evidence = bool(context.evidence_summary or context.raw_output)
        manual_review_required = (
            severity in _HIGH_RISK_SEVERITY
            or confidence != "high"
            or not has_evidence
        )

        ai_summary = self._summary(context, severity, has_evidence)
        report_draft = self._report_draft(
            improved_title, context, severity, business_impact, remediation, cwe, owasp
        )

        return TriageResult(
            title=improved_title,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            category=category,
            cwe=cwe,
            owasp=owasp,
            business_impact=business_impact,
            remediation=remediation,
            report_draft=report_draft,
            manual_review_required=manual_review_required,
            ai_summary=ai_summary,
        )

    # -- helpers -----------------------------------------------------------
    def _resolve_taxonomy(self, ctx: FindingContext, category: str) -> tuple[str, str]:
        cwe = ctx.cwe or _CATEGORY_MAP.get(category, ("CWE-Unknown", ""))[0]
        owasp = ctx.owasp or _CATEGORY_MAP.get(category, ("", "A05:2021 Security Misconfiguration"))[1]
        return cwe, owasp

    def _improve_title(self, ctx: FindingContext) -> str:
        base = ctx.title.strip()
        if ctx.asset_value and ctx.asset_value not in base:
            return f"{base} on {ctx.asset_value}"
        return base

    def _impact_from_severity(self, severity: str, ctx: FindingContext) -> str:
        scale = {
            "critical": "Could lead to full compromise of the affected asset.",
            "high": "Could allow significant unauthorized access or data exposure.",
            "medium": "May weaken the security posture and aid further attacks.",
            "low": "Limited direct impact but worth remediating.",
            "info": "Informational; no direct security impact identified.",
        }
        impact = scale.get(severity, scale["info"])
        if ctx.asset_value:
            impact += f" Affected asset: {ctx.asset_value}."
        return impact

    def _remediation(self, ctx: FindingContext, category: str) -> str:
        if ctx.remediation:
            return ctx.remediation
        generic = {
            "secret": "Rotate the exposed credential and purge it from version control history.",
            "dependency": "Upgrade the affected dependency to a patched version.",
            "sast": "Review the flagged code path and apply secure-coding fixes.",
            "zap-passive": "Apply the missing security headers / configuration hardening.",
            "nuclei-template": "Validate the reported exposure and apply vendor guidance.",
        }
        return generic.get(category, "Investigate and remediate per the finding details.")

    def _summary(self, ctx: FindingContext, severity: str, has_evidence: bool) -> str:
        parts = [
            f"Finding '{ctx.title}' reported by {ctx.scanner_name or 'unknown scanner'}",
            f"at {severity} severity.",
        ]
        if has_evidence:
            parts.append("Evidence is present and should be manually verified.")
        else:
            parts.append("No confirming evidence attached — manual review required.")
        return " ".join(parts)

    def _report_draft(
        self,
        title: str,
        ctx: FindingContext,
        severity: str,
        impact: str,
        remediation: str,
        cwe: str,
        owasp: str,
    ) -> str:
        evidence = ctx.evidence_summary or "(no machine-collected evidence; manual review required)"
        return (
            f"## {title}\n\n"
            f"**Severity:** {severity}\n\n"
            f"**Category:** {ctx.category or 'n/a'} ({cwe}, {owasp})\n\n"
            f"### Summary\n{ctx.description or ctx.title}\n\n"
            f"### Evidence\n{evidence}\n\n"
            f"### Impact\n{impact}\n\n"
            f"### Remediation\n{remediation}\n"
        )
