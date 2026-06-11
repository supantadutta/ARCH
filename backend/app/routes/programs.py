"""Program management routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import Program
from app.schemas.schemas import ProgramCreate, ProgramOut, ProgramUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/programs", tags=["programs"])


@router.get("", response_model=list[ProgramOut])
def list_programs(db: Session = Depends(get_db)):
    return db.query(Program).order_by(Program.created_at.desc()).all()


@router.post("", response_model=ProgramOut, status_code=201)
def create_program(
    payload: ProgramCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
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
def get_program(program_id: int, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    return program


@router.patch("/{program_id}", response_model=ProgramOut)
def update_program(program_id: int, payload: ProgramUpdate, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(program, key, value)
    db.commit()
    db.refresh(program)
    record_audit(db, action="program.update", target=f"program:{program_id}")
    return program


@router.delete("/{program_id}", status_code=204)
def delete_program(program_id: int, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    db.delete(program)
    db.commit()
    record_audit(db, action="program.delete", target=f"program:{program_id}")
