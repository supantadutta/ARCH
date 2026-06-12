"""Routes for the advanced authorized bug-hunting modules.

All endpoints are role-gated and program-access-gated. Modules that send
requests default to dry-run and are scope/kill-switch gated inside the service
layer. Risky outcomes are recorded as ``needs_review`` findings.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.advanced import api_security, business_logic, payment_review, permission_matrix
from app.advanced.access_control import compare_access
from app.advanced.auth_crawler import run_authenticated_crawl
from app.advanced.crypto import encrypt
from app.advanced.payment_review import SandboxRequiredError
from app.advanced.source_route import analyze_repo
from app.advanced.workflow_state import analyze_workflow
from app.auth import (
    ROLE_ADMIN,
    ROLE_RESEARCHER,
    ROLE_TRIAGER,
    Principal,
    ensure_program_access,
    require_role,
)
from app.database import get_db
from app.models import (
    ApiEndpoint,
    Checklist,
    PermissionRule,
    Program,
    SourceRoute,
    TestAccount,
    WorkflowDefinition,
)
from app.policy.scope_guard import ScopeError
from app.schemas.schemas import (
    ApiEndpointOut,
    ChecklistOut,
    PermissionRuleCreate,
    PermissionRuleOut,
    SourceRouteOut,
    TestAccountCreate,
    TestAccountOut,
    WorkflowDefinitionCreate,
    WorkflowDefinitionOut,
)

router = APIRouter(prefix="/programs/{program_id}", tags=["advanced"])

# Roles permitted to operate the advanced modules.
_OPERATOR = require_role(ROLE_RESEARCHER, ROLE_TRIAGER)


def _account_out(a: TestAccount) -> TestAccountOut:
    return TestAccountOut(
        id=a.id, program_id=a.program_id, label=a.label, role=a.role, username=a.username,
        login_url=a.login_url, is_authorized=a.is_authorized, has_secret=bool(a.encrypted_secret),
        has_session=bool(a.encrypted_session), notes=a.notes, created_at=a.created_at,
    )


# --- Test accounts (authorized only) -------------------------------------
@router.get("/test-accounts", response_model=list[TestAccountOut])
def list_test_accounts(
    program_id: int, db: Session = Depends(get_db), _: Principal = Depends(ensure_program_access)
):
    rows = db.query(TestAccount).filter(TestAccount.program_id == program_id).all()
    return [_account_out(a) for a in rows]


@router.post("/test-accounts", response_model=TestAccountOut, status_code=201)
def create_test_account(
    program_id: int,
    payload: TestAccountCreate,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_ADMIN)),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    acct = TestAccount(
        program_id=program_id,
        label=payload.label,
        role=payload.role,
        username=payload.username,
        encrypted_secret=encrypt(payload.secret),  # stored encrypted
        login_url=payload.login_url,
        is_authorized=payload.is_authorized,
        notes=payload.notes,
    )
    db.add(acct)
    db.commit()
    db.refresh(acct)
    from app.services.audit import record_audit

    record_audit(
        db, action="test_account.create", actor=actor.email, target=f"program:{program_id}",
        detail=f"label={acct.label} role={acct.role} authorized={acct.is_authorized}",
    )
    return _account_out(acct)


# --- API security: import + inventory + test cases -----------------------
class ApiImportRequest(BaseModel):
    content: str


@router.post("/api/import")
def api_import(
    program_id: int,
    payload: ApiImportRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    try:
        return api_security.import_collection(db, program_id, payload.content, actor=actor.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/endpoints", response_model=list[ApiEndpointOut])
def list_api_endpoints(
    program_id: int, db: Session = Depends(get_db), _: Principal = Depends(ensure_program_access)
):
    return db.query(ApiEndpoint).filter(ApiEndpoint.program_id == program_id).all()


@router.get("/api/endpoints/{endpoint_id}/test-cases")
def endpoint_test_cases(
    program_id: int, endpoint_id: int, db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    ep = db.get(ApiEndpoint, endpoint_id)
    if not ep or ep.program_id != program_id:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"endpoint_id": endpoint_id, "test_cases": api_security.generate_authorization_test_cases(ep)}


# --- Access control comparator (safe, default dry-run) -------------------
class AccessControlRequest(BaseModel):
    account_a_id: int
    account_b_id: int
    target_urls: list[str]
    dry_run: bool = True


@router.post("/access-control/compare")
def access_control_compare(
    program_id: int,
    payload: AccessControlRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    try:
        return compare_access(
            db, program_id, payload.account_a_id, payload.account_b_id,
            payload.target_urls, dry_run=payload.dry_run, actor=actor.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# --- Permission matrix ----------------------------------------------------
@router.get("/permission-rules", response_model=list[PermissionRuleOut])
def list_permission_rules(
    program_id: int, db: Session = Depends(get_db), _: Principal = Depends(ensure_program_access)
):
    return db.query(PermissionRule).filter(PermissionRule.program_id == program_id).all()


@router.post("/permission-rules", response_model=PermissionRuleOut, status_code=201)
def add_permission_rule(
    program_id: int,
    payload: PermissionRuleCreate,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(ROLE_ADMIN)),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    rule = PermissionRule(program_id=program_id, **payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


class PermissionEvalRequest(BaseModel):
    observations: list[dict]


@router.post("/permission-matrix/evaluate")
def permission_matrix_evaluate(
    program_id: int,
    payload: PermissionEvalRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    return permission_matrix.evaluate_matrix(db, program_id, payload.observations, actor=actor.email)


# --- Business logic assistant (checklists; no requests) ------------------
class BusinessLogicRequest(BaseModel):
    workflow_kind: str


@router.post("/business-logic/checklist", response_model=ChecklistOut, status_code=201)
def business_logic_checklist(
    program_id: int,
    payload: BusinessLogicRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    return business_logic.generate_checklist(db, program_id, payload.workflow_kind, actor=actor.email)


# --- Workflow state tester -----------------------------------------------
@router.post("/workflows", response_model=WorkflowDefinitionOut, status_code=201)
def create_workflow(
    program_id: int,
    payload: WorkflowDefinitionCreate,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(ROLE_ADMIN, ROLE_RESEARCHER, ROLE_TRIAGER)),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    wf = WorkflowDefinition(
        program_id=program_id, name=payload.name, kind=payload.kind,
        steps=json.dumps(payload.steps),
    )
    db.add(wf)
    db.commit()
    db.refresh(wf)
    return wf


class WorkflowAnalyzeRequest(BaseModel):
    observed_steps: list[str]
    token_events: list[dict] = []


@router.post("/workflows/{workflow_id}/analyze")
def workflow_analyze(
    program_id: int,
    workflow_id: int,
    payload: WorkflowAnalyzeRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    try:
        return analyze_workflow(
            db, program_id, workflow_id, payload.observed_steps, payload.token_events, actor=actor.email
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- Payment workflow review (sandbox only) ------------------------------
class PaymentReviewRequest(BaseModel):
    observed_params: list[str] = []
    sandbox_confirmed: bool = False


@router.post("/payment-review/checklist", response_model=ChecklistOut, status_code=201)
def payment_review_checklist(
    program_id: int,
    payload: PaymentReviewRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    try:
        return payment_review.generate_payment_checklist(
            db, program_id, payload.observed_params, payload.sandbox_confirmed, actor=actor.email
        )
    except SandboxRequiredError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --- Source route analyzer (authorized local repos) ----------------------
class SourceAnalyzeRequest(BaseModel):
    repo_path: str


@router.post("/source-routes/analyze")
def source_routes_analyze(
    program_id: int,
    payload: SourceAnalyzeRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    try:
        return analyze_repo(db, program_id, payload.repo_path, actor=actor.email)
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=exc.decision.reason) from exc


@router.get("/source-routes", response_model=list[SourceRouteOut])
def list_source_routes(
    program_id: int, db: Session = Depends(get_db), _: Principal = Depends(ensure_program_access)
):
    return db.query(SourceRoute).filter(SourceRoute.program_id == program_id).all()


# --- Authenticated crawler (authorized account, default dry-run) ---------
class AuthCrawlRequest(BaseModel):
    account_id: int
    start_url: str
    dry_run: bool = True


@router.post("/auth-crawl")
def auth_crawl(
    program_id: int,
    payload: AuthCrawlRequest,
    db: Session = Depends(get_db),
    actor: Principal = Depends(_OPERATOR),
    __: Principal = Depends(ensure_program_access),
):
    try:
        return run_authenticated_crawl(
            db, program_id, payload.account_id, payload.start_url,
            dry_run=payload.dry_run, actor=actor.email,
        )
    except ScopeError as exc:
        reason = getattr(exc, "decision", None)
        raise HTTPException(status_code=403, detail=getattr(reason, "reason", str(exc))) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# --- Checklists listing ---------------------------------------------------
@router.get("/checklists", response_model=list[ChecklistOut])
def list_checklists(
    program_id: int, db: Session = Depends(get_db), _: Principal = Depends(ensure_program_access)
):
    return db.query(Checklist).filter(Checklist.program_id == program_id).order_by(Checklist.created_at.desc()).all()
