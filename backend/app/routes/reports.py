"""Report generation routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import Finding, Report
from app.reports.report_generator import generate_report_markdown, write_report_to_disk
from app.schemas.schemas import ReportOut
from app.services.audit import record_audit

router = APIRouter(tags=["reports"])


@router.post("/findings/{finding_id}/report", response_model=ReportOut, status_code=201)
def generate_report(
    finding_id: int,
    db: Session = Depends(get_db),
    actor: str = Depends(require_api_key),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    title, markdown = generate_report_markdown(db, finding)
    path = write_report_to_disk(finding_id, markdown)

    report = Report(
        program_id=finding.program_id,
        finding_id=finding.id,
        title=title,
        content_markdown=markdown,
        file_path=path,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    record_audit(
        db,
        action="report.generate",
        actor=actor,
        target=f"finding:{finding_id}",
        detail=path,
    )
    return report


@router.get("/programs/{program_id}/reports", response_model=list[ReportOut])
def list_reports(program_id: int, db: Session = Depends(get_db)):
    return (
        db.query(Report)
        .filter(Report.program_id == program_id)
        .order_by(Report.created_at.desc())
        .all()
    )


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
def get_report_markdown(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.content_markdown
