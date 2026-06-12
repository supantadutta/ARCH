"""PermissionMatrixTester — compare expected vs actual access per role.

An admin defines a permission matrix (``PermissionRule`` rows: role × resource ×
action → allow/deny). The tester compares *observed* access (entered by a tester
or produced by other safe modules) against the expected matrix and flags
mismatches. Supports guest / user / manager / admin and custom roles.

This module performs no requests itself — it evaluates observations, so it can
never accidentally exploit anything. Mismatches indicating excess access are
raised as ``needs_review`` findings.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Finding, PermissionRule
from app.services.audit import record_audit

STANDARD_ROLES = ("guest", "user", "manager", "admin")


def _rule_for(rules: list[PermissionRule], role: str, resource: str, action: str):
    for r in rules:
        if r.role == role and r.resource == resource and r.action.upper() == action.upper():
            return r
    return None


def evaluate_matrix(
    db: Session, program_id: int, observations: list[dict], actor: str = "system"
) -> dict:
    """Compare observed access against the expected matrix.

    ``observations`` items: ``{role, resource, action, accessible: bool}``.
    Returns a summary and raises findings for excess-access mismatches.
    """
    rules = db.query(PermissionRule).filter(PermissionRule.program_id == program_id).all()
    mismatches = []
    findings_created = 0

    for obs in observations:
        role = obs.get("role")
        resource = obs.get("resource")
        action = (obs.get("action") or "GET").upper()
        accessible = bool(obs.get("accessible"))
        rule = _rule_for(rules, role, resource, action)
        if not rule:
            continue  # no expectation defined for this cell
        expected_allow = rule.expected_access == "allow"

        if accessible and not expected_allow:
            # EXCESS access — security-relevant. Raise a finding for review.
            mismatches.append({"role": role, "resource": resource, "action": action, "type": "excess_access"})
            db.add(
                Finding(
                    program_id=program_id,
                    title=f"Permission matrix violation: {role} can {action} {resource}",
                    description=(
                        f"Role '{role}' was observed able to access '{resource}' ({action}) "
                        f"but the permission matrix expects this to be DENIED."
                    ),
                    severity="high",
                    confidence="low",
                    status="needs_review",
                    category="permission_matrix",
                    cwe="CWE-285",
                    owasp="A01:2021 Broken Access Control",
                    evidence_summary=f"expected=deny observed=accessible role={role} {action} {resource}",
                    scanner_name="permission_matrix",
                    manual_review_required=True,
                )
            )
            findings_created += 1
        elif not accessible and expected_allow:
            # Functional gap (not a security issue) — report as informational.
            mismatches.append({"role": role, "resource": resource, "action": action, "type": "missing_access"})

    record_audit(
        db, action="permission_matrix.evaluate", actor=actor, target=f"program:{program_id}",
        decision="info", detail=f"observations={len(observations)} mismatches={len(mismatches)} findings={findings_created}",
        commit=False,
    )
    db.commit()
    return {"observations": len(observations), "mismatches": mismatches, "findings_created": findings_created}


def matrix_view(db: Session, program_id: int) -> dict:
    """Return the defined permission matrix grouped by role."""
    rules = db.query(PermissionRule).filter(PermissionRule.program_id == program_id).all()
    out: dict[str, list[dict]] = {}
    for r in rules:
        out.setdefault(r.role, []).append(
            {"resource": r.resource, "action": r.action, "expected_access": r.expected_access}
        )
    return out
