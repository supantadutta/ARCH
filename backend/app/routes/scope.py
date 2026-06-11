"""Scope management routes.

Adding a scope item is a security-sensitive action: it expands what the
platform is authorized to scan. Every change is audited.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import Program, ScopeItem
from app.policy.scope_guard import is_target_in_scope
from app.schemas.schemas import ScopeItemCreate, ScopeItemOut
from app.services.audit import record_audit

router = APIRouter(prefix="/programs/{program_id}/scope", tags=["scope"])


@router.get("", response_model=list[ScopeItemOut])
def list_scope(program_id: int, db: Session = Depends(get_db)):
    return db.query(ScopeItem).filter(ScopeItem.program_id == program_id).all()


@router.post("", response_model=ScopeItemOut, status_code=201)
def add_scope(
    program_id: int,
    payload: ScopeItemCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    item = ScopeItem(
        program_id=program_id,
        scope_type=payload.scope_type.value,
        value=payload.value,
        is_allowed=payload.is_allowed,
        notes=payload.notes,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    record_audit(
        db,
        action="scope.add",
        actor=actor,
        target=f"program:{program_id}",
        decision="allowed" if payload.is_allowed else "rejected",
        detail=f"{payload.scope_type.value}={payload.value} is_allowed={payload.is_allowed}",
    )
    return item


@router.delete("/{item_id}", status_code=204)
def remove_scope(program_id: int, item_id: int, db: Session = Depends(get_db)):
    item = db.get(ScopeItem, item_id)
    if not item or item.program_id != program_id:
        raise HTTPException(status_code=404, detail="Scope item not found")
    db.delete(item)
    db.commit()
    record_audit(db, action="scope.remove", target=f"program:{program_id}", detail=f"item:{item_id}")


@router.get("/check")
def check_scope(program_id: int, target: str, db: Session = Depends(get_db)):
    """Convenience endpoint: evaluate whether a target is in scope."""
    decision = is_target_in_scope(db, program_id, target)
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "normalized_target": decision.normalized_target,
        "scope_type": decision.scope_type,
    }
