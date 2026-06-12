"""Asset inventory routes — with pagination, search and program access."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth import ROLE_RESEARCHER, ROLE_TRIAGER, Principal, ensure_program_access, require_role
from app.database import get_db
from app.models import Asset, Program
from app.schemas.schemas import AssetCreate, AssetOut, Page
from app.services.pagination import paginate

router = APIRouter(prefix="/programs/{program_id}/assets", tags=["assets"])


@router.get("", response_model=Page)
def list_assets(
    program_id: int,
    q: str | None = Query(default=None, description="Search value/technologies"),
    asset_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    query = db.query(Asset).filter(Asset.program_id == program_id)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Asset.value.ilike(like), Asset.technologies.ilike(like)))
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if status:
        query = query.filter(Asset.status == status)
    query = query.order_by(Asset.risk_score.desc())
    return paginate(query, limit, offset, AssetOut.model_validate)


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    program_id: int,
    payload: AssetCreate,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(ROLE_RESEARCHER, ROLE_TRIAGER)),
):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    asset = Asset(program_id=program_id, **payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    program_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    asset = db.get(Asset, asset_id)
    if not asset or asset.program_id != program_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset
