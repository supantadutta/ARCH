"""PaymentWorkflowReviewModule — safe payment-flow review (sandbox/staging only).

Detects payment-related parameters and generates a SAFE manual review
checklist. It performs no transactions and never attempts real payment abuse.
By policy it operates only against sandbox/staging environments
(``PAYMENT_SANDBOX_ONLY``); callers must confirm a non-production target.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Checklist
from app.services.audit import record_audit

# Payment-related parameter names of interest.
PAYMENT_PARAMS = (
    "price", "amount", "discount", "coupon", "quantity", "currency", "plan_id",
    "payment_status", "refund_status", "total", "subtotal", "tax", "fee",
)


class SandboxRequiredError(RuntimeError):
    """Raised when a payment review is attempted outside sandbox/staging."""


def detect_payment_params(names: list[str]) -> list[str]:
    """Return the payment-related parameters present in a list of names."""
    out: list[str] = []
    for n in names:
        ln = (n or "").lower()
        if ln in PAYMENT_PARAMS or any(p in ln for p in PAYMENT_PARAMS):
            if n not in out:
                out.append(n)
    return out


def generate_payment_checklist(
    db: Session,
    program_id: int,
    observed_params: list[str],
    sandbox_confirmed: bool,
    actor: str = "system",
) -> Checklist:
    """Generate a payment-review checklist. Requires sandbox confirmation."""
    if settings.payment_sandbox_only and not sandbox_confirmed:
        raise SandboxRequiredError(
            "Payment review is restricted to sandbox/staging. Confirm a non-production "
            "target (sandbox_confirmed=true) to proceed."
        )

    detected = detect_payment_params(observed_params)
    md = [
        "# Payment workflow review checklist (sandbox/staging only)",
        "",
        "_Review-only. No transactions are performed; no real payment abuse._",
        "",
        f"Detected payment parameters: {', '.join(detected) or '(none provided)'}",
        "",
        "- [ ] Confirm all monetary values (price, amount, total, discount) are recomputed "
        "server-side and client-supplied values are ignored.",
        "- [ ] Verify quantity and currency cannot be manipulated to change the charged amount.",
        "- [ ] Check coupon/discount logic for reuse, stacking, and ownership across accounts.",
        "- [ ] Confirm plan_id changes enforce server-side entitlement and price validation.",
        "- [ ] Verify payment_status / refund_status cannot be set directly by the client.",
        "- [ ] Confirm refunds cannot exceed the original charge.",
        "",
        "> ⚠️ Sandbox/staging only. Any state-changing test requires manual approval.",
    ]
    checklist = Checklist(
        program_id=program_id,
        kind="payment_review",
        title="Payment workflow review (sandbox only)",
        content_markdown="\n".join(md),
    )
    db.add(checklist)
    record_audit(
        db, action="payment_review.checklist", actor=actor, target=f"program:{program_id}",
        decision="info", detail=f"params={len(detected)} sandbox_confirmed={sandbox_confirmed}",
        commit=False,
    )
    db.commit()
    db.refresh(checklist)
    return checklist
