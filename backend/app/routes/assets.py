"""Asset inventory routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Program
from app.schemas.schemas import AssetCreate, AssetOut

router = APIRouter(prefix="/programs/{program_id}/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(program_id: int, db: Session = Depends(get_db)):
    return (
        db.query(Asset)
        .filter(Asset.program_id == program_id)
        .order_by(Asset.risk_score.desc())
        .all()
    )


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(program_id: int, payload: AssetCreate, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(status_code=404, detail="Program not found")
    asset = Asset(program_id=program_id, **payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(program_id: int, asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset or asset.program_id != program_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset
