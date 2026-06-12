"""Program management routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth import ROLE_ADMIN, Principal, get_principal, require_role
from app.database import get_db
from app.models import Program, ProgramMember
from app.schemas.schemas import Page, ProgramCreate, ProgramOut, ProgramUpdate
from app.services.audit import record_audit
from app.services.pagination import paginate

router = APIRouter(prefix="/programs", tags=["programs"])


@router.get("", response_model=Page)
def list_programs(
    q: str | None = Query(default=None, description="Search by name"),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    query = db.query(Program)
    # Non-admin users only see programs they are assigned to.
    if not principal.is_admin and principal.user_id is not None:
        query = query.join(ProgramMember, ProgramMember.program_id == Program.id).filter(
            ProgramMember.user_id == principal.user_id
        )
    if q:
        query = query.filter(Program.name.ilike(f"%{q}%"))
    if status:
        query = query.filter(Program.status == status)
    query = query.order_by(Program.created_at.desc())
    return paginate(query, limit, offset, ProgramOut.model_validate)


@router.post("", response_model=ProgramOut, status_code=201)
def create_program(
    payload: ProgramCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(ROLE_ADMIN)),
):
    actor = principal.email
    program = Program(**payload.model_dump())
    db.add(program)
    db.commit()
    db.refresh(program)
    record_audit(
        db,
        action="program.create",
        actor=actor,
        target=f"program:{program.id}",
        detail=program.name,
    )
    return program


@router.get("/{program_id}", response_model=ProgramOut)
def get_program(
    program_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    return program


@router.patch("/{program_id}", response_model=ProgramOut)
def update_program(
    program_id: int,
    payload: ProgramUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(ROLE_ADMIN)),
):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(program, key, value)
    db.commit()
    db.refresh(program)
    record_audit(db, action="program.update", actor=principal.email, target=f"program:{program_id}")
    return program


@router.delete("/{program_id}", status_code=204)
def delete_program(
    program_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(ROLE_ADMIN)),
):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    db.delete(program)
    db.commit()
    record_audit(db, action="program.delete", actor=principal.email, target=f"program:{program_id}")
