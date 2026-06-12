"""WorkflowStateTester — model workflows and detect state anomalies.

Workflows are modeled as ordered states. Given an *observed* sequence of steps
(and optional token-usage events captured during authorized manual testing),
this analyzer detects skipped steps, repeated steps, expired-token reuse,
invite reuse, and missing state validation.

It analyzes observations only — it never drives a state-changing workflow.
State-changing tests must be performed manually with explicit approval; this
module raises ``needs_review`` findings and a checklist.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.models import Finding, WorkflowDefinition
from app.services.audit import record_audit


def analyze_sequence(expected_steps: list[str], observed_steps: list[str]) -> list[dict]:
    """Compare an observed step sequence against the expected ordered steps."""
    issues: list[dict] = []
    seen: set[str] = set()
    expected_index = {s: i for i, s in enumerate(expected_steps)}
    last_idx = -1

    for step in observed_steps:
        if step in seen:
            issues.append({"type": "repeated_step", "step": step})
        seen.add(step)
        if step in expected_index:
            idx = expected_index[step]
            if idx < last_idx:
                issues.append({"type": "out_of_order_step", "step": step})
            last_idx = max(last_idx, idx)

    # Skipped steps: expected steps that appear before the furthest-reached step
    # but were never observed.
    reached = max([expected_index.get(s, -1) for s in observed_steps] + [-1])
    for s, i in expected_index.items():
        if i < reached and s not in seen:
            issues.append({"type": "skipped_step", "step": s})

    return issues


def analyze_token_events(token_events: list[dict]) -> list[dict]:
    """Detect expired-token reuse and invite reuse from observed events."""
    issues: list[dict] = []
    used: set[str] = set()
    for ev in token_events or []:
        token = ev.get("token")
        kind = ev.get("kind", "token")
        if not token:
            continue
        if token in used:
            issues.append({"type": f"{kind}_reuse", "token": "<redacted>"})
        used.add(token)
        if ev.get("expired"):
            issues.append({"type": "expired_token_reuse", "token": "<redacted>"})
    return issues


def analyze_workflow(
    db: Session,
    program_id: int,
    workflow_id: int,
    observed_steps: list[str],
    token_events: list[dict] | None = None,
    actor: str = "system",
) -> dict:
    """Analyze a workflow run for state anomalies and raise findings for review."""
    wf = db.get(WorkflowDefinition, workflow_id)
    if not wf or wf.program_id != program_id:
        raise ValueError("Workflow not found for this program.")
    expected = json.loads(wf.steps or "[]")

    issues = analyze_sequence(expected, observed_steps) + analyze_token_events(token_events or [])
    findings_created = 0
    for issue in issues:
        db.add(
            Finding(
                program_id=program_id,
                title=f"Workflow state anomaly ({issue['type']}) in '{wf.name}'",
                description=(
                    f"Observed workflow run showed a '{issue['type']}' anomaly. "
                    "Validate the missing/abusable state transition manually."
                ),
                severity="medium",
                confidence="low",
                status="needs_review",
                category="workflow",
                cwe="CWE-841",
                owasp="A04:2021 Insecure Design",
                evidence_summary=json.dumps(issue),
                scanner_name="workflow_state",
                manual_review_required=True,
            )
        )
        findings_created += 1

    record_audit(
        db, action="workflow.analyze", actor=actor, target=f"program:{program_id}",
        decision="info", detail=f"workflow={workflow_id} issues={len(issues)} findings={findings_created}",
        commit=False,
    )
    db.commit()
    return {"workflow": wf.name, "issues": issues, "findings_created": findings_created}
