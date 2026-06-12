"""Pydantic request/response schemas.

These mirror the ORM models but expose only the fields appropriate for the
API surface, with validation for enumerated values.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class ScopeType(str, Enum):
    domain = "domain"
    wildcard_domain = "wildcard_domain"
    ip = "ip"
    cidr = "cidr"
    repo = "repo"
    mobile_app = "mobile_app"


class JobType(str, Enum):
    recon = "recon"
    nuclei = "nuclei"
    zap_baseline = "zap_baseline"
    semgrep = "semgrep"
    gitleaks = "gitleaks"
    trivy = "trivy"
    ai_triage = "ai_triage"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class FindingStatus(str, Enum):
    new = "new"
    auto_validating = "auto_validating"
    needs_review = "needs_review"
    confirmed = "confirmed"
    false_positive = "false_positive"
    submitted = "submitted"
    resolved = "resolved"
    retest = "retest"
    closed = "closed"


# --------------------------------------------------------------------------
# Program
# --------------------------------------------------------------------------
class ProgramBase(BaseModel):
    name: str
    description: str | None = None
    status: str = "active"


class ProgramCreate(ProgramBase):
    pass


class ProgramUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None


class ProgramOut(ProgramBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------
# ScopeItem
# --------------------------------------------------------------------------
class ScopeItemBase(BaseModel):
    scope_type: ScopeType
    value: str
    is_allowed: bool = True
    notes: str | None = None


class ScopeItemCreate(ScopeItemBase):
    pass


class ScopeItemOut(ScopeItemBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    created_at: datetime


# --------------------------------------------------------------------------
# Asset
# --------------------------------------------------------------------------
class AssetBase(BaseModel):
    asset_type: str = "web"
    value: str
    ip_address: str | None = None
    port: int | None = None
    scheme: str | None = None
    status: str = "active"
    technologies: str | None = None
    risk_score: float = 0.0


class AssetCreate(AssetBase):
    pass


class AssetOut(AssetBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    last_seen: datetime | None = None
    created_at: datetime


# --------------------------------------------------------------------------
# ScanJob
# --------------------------------------------------------------------------
class ScanJobCreate(BaseModel):
    job_type: JobType
    target: str
    # Defaults to None so the server falls back to the global DRY_RUN setting.
    dry_run: bool | None = None


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    job_type: str
    status: str
    target: str
    dry_run: bool
    started_at: datetime | None = None
    finished_at: datetime | None = None
    logs: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    error_message: str | None = None
    created_at: datetime


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------
class FindingBase(BaseModel):
    title: str
    description: str | None = None
    severity: Severity = Severity.info
    confidence: Confidence = Confidence.low
    category: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    evidence_summary: str | None = None
    impact: str | None = None
    remediation: str | None = None
    scanner_name: str | None = None
    raw_output: str | None = None
    asset_id: int | None = None


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    status: FindingStatus | None = None
    category: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    impact: str | None = None
    remediation: str | None = None
    manual_review_required: bool | None = None


class FindingOut(FindingBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    status: str
    ai_summary: str | None = None
    duplicate_of: int | None = None
    manual_review_required: bool
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------
# Evidence / Report / Retest / Audit / Settings
# --------------------------------------------------------------------------
class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    finding_id: int
    label: str
    file_path: str | None = None
    content_type: str | None = None
    description: str | None = None
    created_at: datetime


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    finding_id: int
    title: str
    content_markdown: str
    file_path: str | None = None
    created_at: datetime


class RetestTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    finding_id: int
    status: str
    result: str | None = None
    requested_at: datetime
    completed_at: datetime | None = None


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor: str
    action: str
    target: str | None = None
    decision: str
    detail: str | None = None
    created_at: datetime


class SystemSettingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    key: str
    value: str
    description: str | None = None


class KillSwitchUpdate(BaseModel):
    enabled: bool = Field(..., description="Enable or disable the global kill switch")


class TriageResult(BaseModel):
    """Structured response from the AI triage layer."""

    title: str
    severity: Severity
    confidence: Confidence
    category: str
    cwe: str
    owasp: str
    business_impact: str
    remediation: str
    # The exact pieces of *existing* evidence the assessment relied on. Providers
    # may only list evidence that is actually present on the finding — this is
    # how the "do not invent evidence" rule is made auditable.
    evidence_used: list[str] = Field(default_factory=list)
    report_draft: str
    manual_review_required: bool
    ai_summary: str

    def to_structured_json(self) -> dict:
        """Return the canonical structured triage object with the required keys."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "impact": self.business_impact,
            "remediation": self.remediation,
            "evidence_used": list(self.evidence_used),
            "report_draft": self.report_draft,
            "manual_review_required": self.manual_review_required,
        }
