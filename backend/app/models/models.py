"""SQLAlchemy ORM models for AutoBugHunter.

The schema captures the full vulnerability-management lifecycle: programs and
their authorized scope, discovered assets, scan jobs, findings, evidence,
generated reports, retest tasks and an immutable audit trail.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    """Platform operator with a role and (hashed) password for JWT login."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # role: admin, triager, researcher, viewer
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProgramMember(Base):
    """Assignment of a user to a program.

    Program findings are visible only to assigned members (and admins). This is
    the access-control join table behind per-program permissions.
    """

    __tablename__ = "program_members"
    __table_args__ = (UniqueConstraint("program_id", "user_id", name="uq_program_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Program(Base):
    """A bug-bounty / vulnerability-management program."""

    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scope_items: Mapped[list[ScopeItem]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )


class ScopeItem(Base):
    """An explicitly authorized (or explicitly disallowed) scope entry.

    The scope guard consults these rows to decide whether a target may be
    scanned. ``is_allowed`` allows expressing both allow and deny entries.
    """

    __tablename__ = "scope_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    # scope_type: domain, wildcard_domain, ip, cidr, repo, mobile_app
    scope_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(512), index=True)
    is_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    program: Mapped[Program] = relationship(back_populates="scope_items")


class Asset(Base):
    """A discovered asset belonging to a program."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    asset_type: Mapped[str] = mapped_column(String(50), default="web")
    value: Mapped[str] = mapped_column(String(512), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scheme: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active")
    # Stored as a comma-separated list for MVP simplicity.
    technologies: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    program: Mapped[Program] = relationship(back_populates="assets")
    findings: Mapped[list[Finding]] = relationship(back_populates="asset")


class ScanJob(Base):
    """A queued / running / completed scan execution."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    # job_type: recon, nuclei, zap_baseline, semgrep, gitleaks, trivy, ai_triage
    job_type: Mapped[str] = mapped_column(String(50))
    # status: queued, running, completed, failed, cancelled
    status: Mapped[str] = mapped_column(String(50), default="queued", index=True)
    target: Mapped[str] = mapped_column(String(512))
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    # Optional per-job scanner timeout (seconds); falls back to the global
    # SCANNER_TIMEOUT_SECONDS when null.
    timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    logs: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Captured raw scanner output for full traceability (requirement: store
    # stdout, stderr and exit code alongside normalized findings).
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    """A potential vulnerability finding."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # severity: info, low, medium, high, critical
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    # confidence: low, medium, high
    confidence: Mapped[str] = mapped_column(String(20), default="low")
    # status lifecycle (see request spec)
    status: Mapped[str] = mapped_column(String(30), default="new", index=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    duplicate_of: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    # Any potentially risky validation must set this flag true so a human
    # confirms before further action.
    manual_review_required: Mapped[bool] = mapped_column(Boolean, default=True)
    # Evidence-based validation outcome (set by the validation module). One of:
    # unvalidated, evidence_validated, insufficient_evidence, manual_review_required.
    # Validation is *passive* — it reasons only over evidence already collected and
    # never re-attacks or actively probes the target.
    validation_state: Mapped[str] = mapped_column(String(32), default="unvalidated")
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # SLA deadline computed from severity at creation (null => untracked).
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    program: Mapped[Program] = relationship(back_populates="findings")
    asset: Mapped[Asset | None] = relationship(back_populates="findings")
    evidence_items: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    """An evidence artifact attached to a finding (stored on local disk)."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped[Finding] = relationship(back_populates="evidence_items")


class Report(Base):
    """A generated Markdown report for a finding."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(512))
    content_markdown: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RetestTask(Base):
    """A retest task to confirm a finding has been resolved."""

    __tablename__ = "retest_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Immutable audit trail of all security-relevant actions."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # decision: allowed, rejected, info
    decision: Mapped[str] = mapped_column(String(32), default="info")
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class SystemSetting(Base):
    """Key/value store for global runtime settings (e.g. the kill switch)."""

    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ==========================================================================
# Advanced authorized bug-hunting modules
# ==========================================================================
class TestAccount(Base):
    """An AUTHORIZED test account used by the authenticated modules.

    Credentials and session tokens are stored encrypted at rest. An account is
    only usable once an operator explicitly marks it ``is_authorized``. These
    are deliberately provided test accounts — the platform never brute-forces or
    uses real end-user credentials.
    """

    __tablename__ = "test_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(128))
    # role: guest, user, manager, admin, or a custom string
    role: Mapped[str] = mapped_column(String(64), default="user")
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    login_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Encrypted session material captured after an authorized login.
    encrypted_session: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ApiEndpoint(Base):
    """An API endpoint in the inventory (imported or discovered)."""

    __tablename__ = "api_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    path: Mapped[str] = mapped_column(String(1024))
    # source: openapi, swagger, postman, crawl, manual
    source: Mapped[str] = mapped_column(String(32), default="manual")
    # Comma-separated object-id parameters detected (e.g. "user_id,order_id").
    object_id_params: Mapped[str | None] = mapped_column(Text, nullable=True)
    # auth_required: yes, no, unknown
    auth_required: Mapped[str] = mapped_column(String(16), default="unknown")
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PermissionRule(Base):
    """Expected access for a role against a resource/action (permission matrix)."""

    __tablename__ = "permission_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(512))  # endpoint path / resource name
    action: Mapped[str] = mapped_column(String(16), default="GET")
    # expected_access: allow, deny
    expected_access: Mapped[str] = mapped_column(String(16), default="deny")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class WorkflowDefinition(Base):
    """An ordered multi-step workflow used by the workflow-state tester."""

    __tablename__ = "workflow_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(64), default="custom")
    # Ordered step names stored as a JSON array string.
    steps: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Checklist(Base):
    """A generated, human-driven safe test checklist (business logic / payments)."""

    __tablename__ = "checklists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(64), default="business_logic")
    title: Mapped[str] = mapped_column(String(512))
    content_markdown: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SourceRoute(Base):
    """A route extracted from an authorized local source repository."""

    __tablename__ = "source_routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    file_path: Mapped[str] = mapped_column(String(1024))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    route_path: Mapped[str] = mapped_column(String(1024))
    has_authentication: Mapped[bool] = mapped_column(Boolean, default=False)
    has_authorization: Mapped[bool] = mapped_column(Boolean, default=False)
    middleware: Mapped[str | None] = mapped_column(Text, nullable=True)
    mapped_endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("api_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

