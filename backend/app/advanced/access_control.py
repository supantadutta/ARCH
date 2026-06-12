"""AccessControlComparator — safe cross-account object-access testing.

Uses two AUTHORIZED test accounts. For a small set of in-scope object URLs
"owned" by account A, it performs **read-only GET** requests as account B and
compares the responses (status code, body size, JSON key set, sensitive-field
presence). If B can read A's object, a finding is raised — always
``needs_review`` with **redacted, size-capped** evidence.

Hard safety controls:

* Scope-gated per URL, kill-switch gated, rate limited.
* GET only — never state-changing. No login/credential guessing.
* Capped at ``ACCESS_CONTROL_MAX_OBJECTS``; never bulk download.
* Default dry-run: produce a plan without sending any request.
"""

from __future__ import annotations

import json
import time

import requests
from sqlalchemy.orm import Session

from app.advanced.crypto import decrypt
from app.advanced.redaction import json_key_set, redact_json, redact_text
from app.config import settings
from app.models import Finding, TestAccount
from app.policy.scope_guard import ScopeError, validate_scan_request
from app.services.audit import record_audit

_TIMEOUT = 8
_UA = "AutoBugHunter-AccessControl/0.1 (authorized testing only)"


def _session_headers(account: TestAccount) -> dict:
    """Decrypt an account's stored session into request headers.

    The session is stored (encrypted) as a single ``Header: value`` line, e.g.
    ``Authorization: Bearer <token>`` or ``Cookie: session=<token>``.
    """
    raw = decrypt(account.encrypted_session)
    if not raw or ":" not in raw:
        return {}
    name, value = raw.split(":", 1)
    return {name.strip(): value.strip()}


def _safe_get(url: str, headers: dict) -> requests.Response | None:
    try:
        return requests.get(
            url,
            headers={"User-Agent": _UA, **headers},
            timeout=_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None


def compare_access(
    db: Session,
    program_id: int,
    account_a_id: int,
    account_b_id: int,
    target_urls: list[str],
    dry_run: bool = True,
    actor: str = "system",
) -> dict:
    """Compare whether account B can access account A's in-scope objects."""
    a = db.get(TestAccount, account_a_id)
    b = db.get(TestAccount, account_b_id)
    if not a or not b or a.program_id != program_id or b.program_id != program_id:
        raise ValueError("Both test accounts must belong to the program.")
    if not (a.is_authorized and b.is_authorized):
        raise ValueError("Both test accounts must be explicitly authorized.")

    targets = target_urls[: settings.access_control_max_objects]
    plan = []
    findings_created = 0

    a_headers = _session_headers(a)
    b_headers = _session_headers(b)

    for url in targets:
        # Scope check every URL (raises -> rejected + audited).
        try:
            decision = validate_scan_request(db, program_id, url, "access_control")
        except ScopeError as exc:
            record_audit(
                db, action="access_control.rejected", actor=actor, target=url,
                decision="rejected", detail=exc.decision.reason, commit=False,
            )
            plan.append({"url": url, "status": "out_of_scope", "reason": exc.decision.reason})
            continue

        if dry_run:
            plan.append({"url": decision.normalized_target, "status": "planned (dry-run)"})
            continue

        time.sleep(1.0 / max(settings.scanner_rate_limit_per_sec, 0.5))
        resp_a = _safe_get(url, a_headers)
        resp_b = _safe_get(url, b_headers)
        if resp_a is None or resp_b is None:
            plan.append({"url": url, "status": "unreachable"})
            continue

        comparison = _compare(resp_a, resp_b)
        plan.append({"url": url, "status": "compared", **comparison["summary"]})

        # B reading A's object successfully with matching structure => suspicious.
        if comparison["potential_broken_access"]:
            db.add(
                Finding(
                    program_id=program_id,
                    title=f"Possible broken object-level authorization: {url}",
                    description=(
                        "A second authorized test account was able to read an object "
                        "belonging to the first account. Manual verification required."
                    ),
                    severity="high",
                    confidence="low",
                    status="needs_review",
                    category="access_control",
                    cwe="CWE-639",
                    owasp="A01:2021 Broken Access Control",
                    evidence_summary=comparison["evidence"],
                    scanner_name="access_control",
                    manual_review_required=True,
                )
            )
            findings_created += 1

    record_audit(
        db, action="access_control.run", actor=actor, target=f"program:{program_id}",
        decision="info",
        detail=f"a={account_a_id} b={account_b_id} targets={len(targets)} dry_run={dry_run} findings={findings_created}",
        commit=False,
    )
    db.commit()
    return {"targets": len(targets), "dry_run": dry_run, "findings_created": findings_created, "plan": plan}


def _compare(resp_a: requests.Response, resp_b: requests.Response) -> dict:
    """Compare two responses without retaining bulk or sensitive data."""
    size_a, size_b = len(resp_a.content or b""), len(resp_b.content or b"")
    keys_a, keys_b = [], []
    try:
        keys_a = json_key_set(resp_a.json())
        keys_b = json_key_set(resp_b.json())
    except (ValueError, json.JSONDecodeError):
        pass

    # Heuristic: B got 200 and a body of comparable size/shape to A.
    b_ok = resp_b.status_code == 200
    size_close = size_a > 0 and abs(size_a - size_b) <= max(64, int(size_a * 0.2))
    keys_match = bool(keys_a) and keys_a == keys_b
    potential = b_ok and (size_close or keys_match)

    # Build redacted evidence (no bulk data, sensitive fields masked).
    try:
        body_b_redacted = redact_json(resp_b.json())
        body_snippet = json.dumps(body_b_redacted)[: settings.evidence_max_bytes]
    except (ValueError, json.JSONDecodeError):
        body_snippet = redact_text(resp_b.text)

    evidence = (
        f"A: status={resp_a.status_code} size={size_a} keys={keys_a}; "
        f"B: status={resp_b.status_code} size={size_b} keys={keys_b}. "
        f"B body (redacted): {body_snippet}"
    )
    return {
        "potential_broken_access": potential,
        "summary": {
            "a_status": resp_a.status_code,
            "b_status": resp_b.status_code,
            "size_close": size_close,
            "keys_match": keys_match,
        },
        "evidence": evidence[: settings.evidence_max_bytes],
    }
