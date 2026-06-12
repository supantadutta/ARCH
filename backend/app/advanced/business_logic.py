"""BusinessLogicAssistant — generate SAFE manual test checklists.

The assistant analyzes a discovered workflow and produces a human-driven test
checklist. Critically, the AI **never sends requests** — it only creates test
plans and reviews evidence. Checklists contain review instructions (no
exploitation payloads), and any state-changing step is explicitly marked as
requiring manual approval.

Covers: signup, login, password reset, checkout, coupon, wallet, team invite,
role change, file upload, subscription, refund, API key generation.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Checklist
from app.services.audit import record_audit

# Safe, review-only checklist templates. Each item is an observation/verification
# step — never an attack payload. State-changing checks note manual approval.
_TEMPLATES: dict[str, list[str]] = {
    "signup": [
        "Verify email/identity verification cannot be skipped to gain access.",
        "Check that duplicate or normalized emails cannot create conflicting accounts.",
        "Confirm role assigned at signup is the least-privileged default (not admin).",
    ],
    "login": [
        "Confirm rate-limiting / lockout messaging exists (do NOT brute force — observe behaviour only).",
        "Verify session is rotated on login and old tokens are invalidated.",
        "Check that error messages do not reveal whether an account exists.",
    ],
    "password_reset": [
        "Verify reset tokens are single-use, expiring, and bound to the requesting account.",
        "Confirm a reset link for account A cannot be used to change account B (manual approval to test).",
        "Check that reset does not log the user into another account.",
    ],
    "checkout": [
        "Review whether price/quantity are recomputed server-side (client values must not be trusted).",
        "Confirm ownership checks on cart/order objects across accounts.",
        "State-changing purchase tests require manual approval and sandbox only.",
    ],
    "coupon": [
        "Verify coupons cannot be reused beyond their limit or stacked unexpectedly.",
        "Check coupon ownership/scope (one account's coupon usable by another?).",
        "Do not generate or brute-force coupon codes; review provided codes only.",
    ],
    "wallet": [
        "Confirm balance changes are server-authoritative and signed/audited.",
        "Check that wallet object ids are not accessible across accounts (manual approval to test).",
    ],
    "team_invite": [
        "Verify invites are single-use, expiring, and bound to the invited email.",
        "Confirm an invite cannot be reused to join a different team or escalate role.",
    ],
    "role_change": [
        "Confirm only authorized roles can change roles; verify server-side enforcement.",
        "Check that a user cannot elevate their own role (manual approval to test, no automation).",
    ],
    "file_upload": [
        "Review content-type/extension validation and stored-file access control.",
        "Confirm uploaded files are not executable and not accessible across accounts.",
        "Do not upload malware; use benign test files only.",
    ],
    "subscription": [
        "Verify plan changes are server-validated and entitlements update correctly.",
        "Check that cancelling/downgrading cannot retain higher-tier access.",
    ],
    "refund": [
        "Confirm refund amount cannot exceed the original charge (sandbox only).",
        "Verify refund authorization is enforced; state-changing tests need manual approval.",
    ],
    "api_key_generation": [
        "Confirm generated keys are scoped to the owning account and revocable.",
        "Check that one account cannot view or use another account's API key.",
    ],
}

SUPPORTED_WORKFLOWS = tuple(_TEMPLATES.keys())


def generate_checklist(db: Session, program_id: int, workflow_kind: str, actor: str = "system") -> Checklist:
    """Create and store a safe manual test checklist for a workflow kind."""
    items = _TEMPLATES.get(workflow_kind)
    if items is None:
        # Generic fallback checklist for custom/unknown workflows.
        items = [
            "Map the workflow's steps and identify each state-changing action.",
            "For every object id involved, verify cross-account ownership checks.",
            "Confirm steps cannot be skipped, repeated, or replayed.",
            "All state-changing validation requires manual approval — do not automate.",
        ]
    md = [f"# Safe test checklist — {workflow_kind}", "", "_Review-only. The assistant sends no requests._", ""]
    md += [f"- [ ] {item}" for item in items]
    md += [
        "",
        "> ⚠️ Any state-changing or risky validation requires explicit manual approval.",
        "> Only authorized scope and authorized test accounts may be used.",
    ]
    checklist = Checklist(
        program_id=program_id,
        kind=f"business_logic:{workflow_kind}",
        title=f"Business logic checklist: {workflow_kind}",
        content_markdown="\n".join(md),
    )
    db.add(checklist)
    record_audit(
        db, action="business_logic.checklist", actor=actor, target=f"program:{program_id}",
        decision="info", detail=f"workflow={workflow_kind}", commit=False,
    )
    db.commit()
    db.refresh(checklist)
    return checklist
