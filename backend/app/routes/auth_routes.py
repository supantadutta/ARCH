"""Authentication, user management and program membership routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import ROLE_ADMIN, ALL_ROLES, Principal, get_principal, require_role
from app.database import get_db
from app.models import Program, ProgramMember, User
from app.schemas.schemas import (
    LoginRequest,
    MemberCreate,
    MemberOut,
    TokenResponse,
    UserCreate,
    UserOut,
)
from app.security import create_access_token, hash_password, verify_password
from app.services.audit import record_audit

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Exchange email + password for a JWT access token."""
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.is_active or not verify_password(payload.password, user.hashed_password):
        record_audit(db, action="auth.login_failed", target=payload.email, decision="rejected")
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    record_audit(db, action="auth.login", actor=user.email, target=f"user:{user.id}", decision="allowed")
    return TokenResponse(access_token=token, role=user.role, email=user.email)


@router.get("/auth/me", response_model=UserOut)
def me(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    """Return the current user. API-key principals return a synthetic admin."""
    if principal.user_id is None:
        return UserOut(
            id=0, email=principal.email, full_name="API/Service", role=principal.role,
            is_active=True, created_at=__import__("datetime").datetime.now(),
        )
    user = db.get(User, principal.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# --- User management (admin only) ----------------------------------------
@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: Principal = Depends(require_role(ROLE_ADMIN))):
    return db.query(User).order_by(User.id).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_ADMIN)),
):
    if payload.role not in ALL_ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {ALL_ROLES}")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="A user with that email already exists.")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        hashed_password=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_audit(db, action="user.create", actor=actor.email, target=f"user:{user.id}", detail=user.role)
    return user


# --- Program membership (admin only) -------------------------------------
@router.get("/programs/{program_id}/members", response_model=list[MemberOut])
def list_members(
    program_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(ROLE_ADMIN)),
):
    return db.query(ProgramMember).filter(ProgramMember.program_id == program_id).all()


@router.post("/programs/{program_id}/members", response_model=MemberOut, status_code=201)
def add_member(
    program_id: int,
    payload: MemberCreate,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_ADMIN)),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    if not db.get(User, payload.user_id):
        raise HTTPException(status_code=404, detail="User not found")
    existing = (
        db.query(ProgramMember)
        .filter(ProgramMember.program_id == program_id, ProgramMember.user_id == payload.user_id)
        .first()
    )
    if existing:
        return existing
    member = ProgramMember(program_id=program_id, user_id=payload.user_id)
    db.add(member)
    db.commit()
    db.refresh(member)
    record_audit(
        db, action="program.member_added", actor=actor.email,
        target=f"program:{program_id}", detail=f"user:{payload.user_id}",
    )
    return member


@router.delete("/programs/{program_id}/members/{user_id}", status_code=204)
def remove_member(
    program_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_ADMIN)),
):
    member = (
        db.query(ProgramMember)
        .filter(ProgramMember.program_id == program_id, ProgramMember.user_id == user_id)
        .first()
    )
    if member:
        db.delete(member)
        db.commit()
        record_audit(
            db, action="program.member_removed", actor=actor.email,
            target=f"program:{program_id}", detail=f"user:{user_id}",
        )
