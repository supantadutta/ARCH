"""Validation from evidence — safe, passive corroboration of findings.

This module decides whether a finding is *supported by the evidence already
collected*. It is deliberately and strictly **non-intrusive**:

* It NEVER re-scans, re-requests, exploits, or actively probes a target.
* It only reads evidence already attached to the finding (``evidence_summary``,
  ``raw_output``, and stored :class:`Evidence` items).
* It never auto-confirms a risky finding. High/critical severity (or anything
  lacking solid evidence) is flagged ``manual_review_required`` for a human.

The outcome is recorded on ``finding.validation_state``:

* ``evidence_validated``     — concrete evidence supports the finding and it is
  low-risk enough to mark as evidence-backed (a human still confirms status).
* ``manual_review_required`` — evidence exists but the finding is high-risk and
  must be validated by a person before any action.
* ``insufficient_evidence``  — no machine-collected evidence; cannot validate.

Validation annotates; it does not change a finding's lifecycle ``status`` to
``confirmed`` — confirmation remains a deliberate, role-gated human action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Evidence, Finding
from app.services.audit import record_audit

# Severities that always require a human to validate, regardless of evidence.
HIGH_RISK_SEVERITIES = ("high", "critical")

STATE_VALIDATED = "evidence_validated"
STATE_MANUAL = "manual_review_required"
STATE_INSUFFICIENT = "insufficient_evidence"


@dataclass
class ValidationResult:
    """Outcome of an evidence-based validation."""

    finding_id: int
    validation_state: str
    manual_review_required: bool
    evidence_used: list[str] = field(default_factory=list)
    reason: str = ""


def _collect_evidence(db: Session, finding: Finding) -> list[str]:
    """Gather all concrete evidence already attached to a finding (read-only)."""
    items: list[str] = []
    if finding.evidence_summary:
        items.append(finding.evidence_summary.strip())
    if finding.raw_output:
        items.append(finding.raw_output.strip()[:2000])
    rows = db.query(Evidence).filter(Evidence.finding_id == finding.id).all()
    for e in rows:
        label = e.label or "evidence"
        detail = e.description or e.file_path or ""
        items.append(f"{label}: {detail}".strip().rstrip(":").strip())
    # De-duplicate while preserving order and dropping empties.
    seen: set[str] = set()
    return [i for i in items if i and not (i in seen or seen.add(i))]


def validate_finding(db: Session, finding: Finding, actor: str = "system") -> ValidationResult:
    """Validate a single finding from its existing evidence (passive)."""
    evidence = _collect_evidence(db, finding)

    if not evidence:
        state = STATE_INSUFFICIENT
        manual = True
        reason = "No machine-collected evidence is attached; cannot validate automatically."
    elif finding.severity in HIGH_RISK_SEVERITIES:
        # Evidence exists, but high-risk findings must be validated by a human.
        state = STATE_MANUAL
        manual = True
        reason = (
            f"Evidence present, but {finding.severity} severity requires manual "
            "validation before any action."
        )
    elif finding.confidence == "high":
        # Low/medium severity with solid evidence and high confidence: the
        # evidence supports the finding. A human still confirms the status.
        state = STATE_VALIDATED
        manual = False
        reason = "Existing evidence supports this finding (low risk, high confidence)."
    else:
        # Evidence present but confidence is not high — keep it for review.
        state = STATE_MANUAL
        manual = True
        reason = "Evidence present but confidence is not high; manual review recommended."

    finding.validation_state = state
    finding.validated_at = datetime.now(timezone.utc)
    finding.manual_review_required = manual
    # Move a brand-new finding into the review pipeline; never auto-confirm.
    if finding.status in ("new", "auto_validating"):
        finding.status = "needs_review"
    db.add(finding)
    record_audit(
        db,
        action="finding.validate",
        actor=actor,
        target=f"finding:{finding.id}",
        decision="info",
        detail=f"state={state} manual_review_required={manual} evidence_items={len(evidence)}",
        commit=False,
    )
    db.commit()
    db.refresh(finding)
    return ValidationResult(
        finding_id=finding.id,
        validation_state=state,
        manual_review_required=manual,
        evidence_used=evidence,
        reason=reason,
    )


def validate_program(db: Session, program_id: int, actor: str = "system") -> dict:
    """Validate all not-yet-validated findings in a program. Returns a summary."""
    findings = (
        db.query(Finding)
        .filter(Finding.program_id == program_id, Finding.duplicate_of.is_(None))
        .order_by(Finding.id.asc())
        .all()
    )
    counts = {STATE_VALIDATED: 0, STATE_MANUAL: 0, STATE_INSUFFICIENT: 0}
    for f in findings:
        result = validate_finding(db, f, actor=actor)
        counts[result.validation_state] = counts.get(result.validation_state, 0) + 1
    return {"scanned": len(findings), **counts}
