"""Tests for the advanced authorized bug-hunting modules (safety + core logic)."""

from __future__ import annotations

import json

import pytest

from app.advanced import api_security, business_logic, payment_review, permission_matrix
from app.advanced.access_control import compare_access
from app.advanced.auth_crawler import run_authenticated_crawl
from app.advanced.crypto import decrypt, encrypt
from app.advanced.payment_review import SandboxRequiredError
from app.advanced.redaction import redact_json, redact_text
from app.advanced.source_route import analyze_repo
from app.advanced.workflow_state import analyze_sequence, analyze_token_events, analyze_workflow
from app.models import ApiEndpoint, Finding, PermissionRule, WorkflowDefinition
from app.models import TestAccount as Acct  # aliased so pytest doesn't collect the model
from app.policy.scope_guard import ScopeError
from app.services.killswitch import set_kill_switch


# --------------------------------------------------------------------------
# Crypto + redaction (secure storage, no data leakage)
# --------------------------------------------------------------------------
def test_secret_encryption_roundtrip():
    token = encrypt("super-secret-session")
    assert token != "super-secret-session"
    assert decrypt(token) == "super-secret-session"
    assert decrypt(None) is None


def test_redaction_masks_sensitive_and_caps_lists():
    obj = {"password": "x", "email": "a@b.com", "items": list(range(100)), "token": "t"}
    red = redact_json(obj)
    assert red["password"] == "<redacted>"
    assert red["token"] == "<redacted>"
    assert len(red["items"]) <= 5  # never retain bulk data
    assert "<redacted-email>" in redact_text("contact a@b.com 123456789012")


# --------------------------------------------------------------------------
# API security: import + object-id detection + safe test cases
# --------------------------------------------------------------------------
def test_openapi_import_detects_object_ids(db, program_with_scope):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{user_id}": {"get": {"security": [{}]}},
            "/orders/{order_id}": {"delete": {}},
            "/health": {"get": {}},
        },
    }
    res = api_security.import_collection(db, program_with_scope.id, json.dumps(spec))
    assert res["imported"] == 3
    assert res["object_id_endpoints"] == 2
    eps = db.query(ApiEndpoint).filter(ApiEndpoint.program_id == program_with_scope.id).all()
    user_ep = next(e for e in eps if "user_id" in e.path)
    assert "user_id" in (user_ep.object_id_params or "")


def test_authorization_test_cases_are_safe(db, program_with_scope):
    ep = ApiEndpoint(program_id=program_with_scope.id, method="GET", path="/u/{user_id}", object_id_params="user_id")
    db.add(ep); db.commit(); db.refresh(ep)
    cases = api_security.generate_authorization_test_cases(ep)
    text = " ".join(cases).lower()
    assert "do not enumerate" in text or "do not bulk" in text or "one or two" in text
    assert "manual" in text  # state-changing requires manual validation


# --------------------------------------------------------------------------
# Access control comparator (safe: dry-run, authorized accounts, scope)
# --------------------------------------------------------------------------
def _account(db, program, label, authorized=True):
    a = Acct(program_id=program.id, label=label, role="user", is_authorized=authorized)
    db.add(a); db.commit(); db.refresh(a)
    return a


def test_access_control_requires_authorized_accounts(db, program_with_scope):
    a = _account(db, program_with_scope, "A", authorized=True)
    b = _account(db, program_with_scope, "B", authorized=False)
    with pytest.raises(ValueError):
        compare_access(db, program_with_scope.id, a.id, b.id, ["http://localhost/x"], dry_run=True)


def test_access_control_dry_run_sends_no_requests(db, program_with_scope):
    a = _account(db, program_with_scope, "A")
    b = _account(db, program_with_scope, "B")
    # localhost is in program_with_scope; dry-run must only plan.
    res = compare_access(db, program_with_scope.id, a.id, b.id, ["http://localhost/orders/1"], dry_run=True)
    assert res["dry_run"] is True
    assert res["findings_created"] == 0
    assert res["plan"][0]["status"].startswith("planned")


def test_access_control_out_of_scope_is_rejected(db, program_with_scope):
    a = _account(db, program_with_scope, "A")
    b = _account(db, program_with_scope, "B")
    res = compare_access(db, program_with_scope.id, a.id, b.id, ["http://evil.example.net/x"], dry_run=True)
    assert res["plan"][0]["status"] == "out_of_scope"


# --------------------------------------------------------------------------
# Permission matrix
# --------------------------------------------------------------------------
def test_permission_matrix_flags_excess_access(db, program_with_scope):
    db.add(PermissionRule(program_id=program_with_scope.id, role="user", resource="/admin", action="GET", expected_access="deny"))
    db.commit()
    res = permission_matrix.evaluate_matrix(
        db, program_with_scope.id,
        [{"role": "user", "resource": "/admin", "action": "GET", "accessible": True}],
    )
    assert res["findings_created"] == 1
    f = db.query(Finding).filter(Finding.category == "permission_matrix").first()
    assert f.status == "needs_review" and f.manual_review_required is True


def test_permission_matrix_no_finding_when_expected(db, program_with_scope):
    db.add(PermissionRule(program_id=program_with_scope.id, role="admin", resource="/admin", action="GET", expected_access="allow"))
    db.commit()
    res = permission_matrix.evaluate_matrix(
        db, program_with_scope.id,
        [{"role": "admin", "resource": "/admin", "action": "GET", "accessible": True}],
    )
    assert res["findings_created"] == 0


# --------------------------------------------------------------------------
# Business logic assistant (checklists, no requests)
# --------------------------------------------------------------------------
def test_business_logic_checklist_is_review_only(db, program_with_scope):
    cl = business_logic.generate_checklist(db, program_with_scope.id, "checkout")
    assert cl.kind == "business_logic:checkout"
    assert "sends no requests" in cl.content_markdown.lower()
    assert "manual approval" in cl.content_markdown.lower()


# --------------------------------------------------------------------------
# Workflow state tester
# --------------------------------------------------------------------------
def test_analyze_sequence_detects_anomalies():
    expected = ["start", "verify", "checkout", "done"]
    issues = analyze_sequence(expected, ["start", "checkout", "checkout"])
    types = {i["type"] for i in issues}
    assert "repeated_step" in types
    assert "skipped_step" in types  # "verify" skipped before checkout


def test_analyze_token_events_detects_reuse():
    issues = analyze_token_events([
        {"token": "t1", "kind": "invite"},
        {"token": "t1", "kind": "invite"},
        {"token": "t2", "expired": True},
    ])
    types = {i["type"] for i in issues}
    assert "invite_reuse" in types
    assert "expired_token_reuse" in types


def test_workflow_analyze_creates_needs_review_findings(db, program_with_scope):
    wf = WorkflowDefinition(program_id=program_with_scope.id, name="signup", kind="signup", steps=json.dumps(["a", "b", "c"]))
    db.add(wf); db.commit(); db.refresh(wf)
    res = analyze_workflow(db, program_with_scope.id, wf.id, ["a", "c", "a"])
    assert res["findings_created"] >= 1
    f = db.query(Finding).filter(Finding.category == "workflow").first()
    assert f.status == "needs_review"


# --------------------------------------------------------------------------
# Payment review (sandbox only)
# --------------------------------------------------------------------------
def test_payment_review_requires_sandbox(db, program_with_scope):
    with pytest.raises(SandboxRequiredError):
        payment_review.generate_payment_checklist(db, program_with_scope.id, ["price", "coupon"], sandbox_confirmed=False)


def test_payment_review_checklist_detects_params(db, program_with_scope):
    cl = payment_review.generate_payment_checklist(
        db, program_with_scope.id, ["price", "discount", "plan_id", "irrelevant"], sandbox_confirmed=True
    )
    assert "price" in cl.content_markdown and "discount" in cl.content_markdown
    assert "sandbox" in cl.content_markdown.lower()


# --------------------------------------------------------------------------
# Source route analyzer (authorized local repo only)
# --------------------------------------------------------------------------
def test_source_route_rejects_unauthorized_path(db, program_with_scope, monkeypatch):
    import app.config as cfg
    from app.config import Settings
    s = Settings(authorized_scan_paths="")  # no authorized paths
    monkeypatch.setattr(cfg, "settings", s)
    import app.policy.scope_guard as guard
    monkeypatch.setattr(guard, "settings", s)
    with pytest.raises(ScopeError):
        analyze_repo(db, program_with_scope.id, "/etc")


def test_source_route_analyzes_authorized_repo(tmp_path, db, program_with_scope, monkeypatch):
    # Authorize the tmp path and add a matching repo scope entry.
    from app.models import ScopeItem
    import app.config as cfg
    from app.config import Settings
    root = str(tmp_path)
    s = Settings(authorized_scan_paths=root)
    monkeypatch.setattr(cfg, "settings", s)
    import app.policy.scope_guard as guard
    monkeypatch.setattr(guard, "settings", s)
    db.add(ScopeItem(program_id=program_with_scope.id, scope_type="repo", value=root, is_allowed=True))
    db.commit()
    # A FastAPI-style file: one authed route, one unauthenticated route.
    (tmp_path / "api.py").write_text(
        "@router.get('/public')\n"
        "def public():\n    return 1\n\n"
        "@router.get('/me')\n"
        "def me(user=Depends(current_user)):\n    return user\n"
    )
    res = analyze_repo(db, program_with_scope.id, root)
    assert res["routes_extracted"] == 2
    assert res["routes_missing_auth"] == 1  # /public has no auth marker
    assert res["findings_created"] == 1


# --------------------------------------------------------------------------
# Authenticated crawler (safety)
# --------------------------------------------------------------------------
def test_auth_crawl_dry_run_plans_without_requests(db, program_with_scope, monkeypatch):
    import app.advanced.auth_crawler as ac

    def _boom(*a, **k):  # network must NOT be touched in dry-run
        raise AssertionError("dry-run must not send requests")

    monkeypatch.setattr(ac.requests.Session, "get", _boom, raising=False)
    a = _account(db, program_with_scope, "crawler")
    a.login_url = "http://localhost/login"
    a.encrypted_secret = encrypt(json.dumps({"u": "x", "p": "y"}))
    db.commit()
    res = run_authenticated_crawl(db, program_with_scope.id, a.id, "http://localhost/app", dry_run=True)
    assert res["dry_run"] is True
    assert "log in as authorized account" in res["plan"]


def test_auth_crawl_blocked_by_kill_switch(db, program_with_scope):
    set_kill_switch(db, True)
    a = _account(db, program_with_scope, "crawler")
    with pytest.raises(ScopeError):
        run_authenticated_crawl(db, program_with_scope.id, a.id, "http://localhost/app", dry_run=True)


def test_auth_crawl_requires_authorized_account(db, program_with_scope):
    a = _account(db, program_with_scope, "crawler", authorized=False)
    with pytest.raises(ValueError):
        run_authenticated_crawl(db, program_with_scope.id, a.id, "http://localhost/app", dry_run=True)
