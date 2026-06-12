"""Report generation routes — per-finding and program-wide Markdown export."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth import (
    ROLE_RESEARCHER,
    ROLE_TRIAGER,
    Principal,
    ensure_program_access,
    get_principal,
    require_role,
)
from app.database import get_db
from app.models import Finding, Program, Report
from app.reports.report_generator import generate_report_markdown, write_report_to_disk
from app.schemas.schemas import Page, ReportOut
from app.services.audit import record_audit
from app.services.pagination import paginate

router = APIRouter(tags=["reports"])


@router.post("/findings/{finding_id}/report", response_model=ReportOut, status_code=201)
def generate_report(
    finding_id: int,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_role(ROLE_RESEARCHER, ROLE_TRIAGER)),
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
        db, action="report.generate", actor=actor.email,
        target=f"finding:{finding_id}", detail=path,
    )
    return report


@router.get("/programs/{program_id}/reports", response_model=Page)
def list_reports(
    program_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    query = (
        db.query(Report)
        .filter(Report.program_id == program_id)
        .order_by(Report.created_at.desc())
    )
    return paginate(query, limit, offset, ReportOut.model_validate)


@router.get("/programs/{program_id}/report.md", response_class=PlainTextResponse)
def export_program_report_markdown(
    program_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(ensure_program_access),
):
    """Aggregate all findings in a program into a single Markdown report."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    findings = (
        db.query(Finding)
        .filter(Finding.program_id == program_id, Finding.duplicate_of.is_(None))
        .order_by(Finding.severity.desc(), Finding.id.asc())
        .all()
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Program Report — {program.name}",
        "",
        f"_Generated {now}. Authorized scope only._",
        "",
        f"Total findings (excluding duplicates): **{len(findings)}**",
        "",
    ]
    for f in findings:
        review = " ⚠️ manual review required" if f.manual_review_required else ""
        lines.append(f"## [{f.severity.upper()}] {f.title}{review}")
        lines.append("")
        lines.append(f"- **Status:** {f.status}  ")
        lines.append(f"- **Confidence:** {f.confidence}  ")
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}  ")
        if f.owasp:
            lines.append(f"- **OWASP:** {f.owasp}  ")
        lines.append("")
        lines.append(f"**Summary:** {f.description or f.ai_summary or f.title}")
        lines.append("")
        lines.append(f"**Evidence:** {f.evidence_summary or '(none — manual review required)'}")
        lines.append("")
        lines.append(f"**Impact:** {f.impact or 'Not assessed.'}")
        lines.append("")
        lines.append(f"**Remediation:** {f.remediation or 'Pending.'}")
        lines.append("")
        lines.append("---")
        lines.append("")
    record_audit(db, action="report.program_export", target=f"program:{program_id}", detail=f"findings={len(findings)}")
    return "\n".join(lines)


def _load_report_with_access(report_id: int, db: Session, principal: Principal) -> Report:
    from app.auth import user_can_access_program

    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not user_can_access_program(db, principal, report.program_id):
        raise HTTPException(status_code=403, detail="You are not assigned to this program.")
    return report


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    return _load_report_with_access(report_id, db, principal)


@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
def get_report_markdown(
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    return _load_report_with_access(report_id, db, principal).content_markdown
