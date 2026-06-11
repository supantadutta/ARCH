"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(255)),
        sa.Column("role", sa.String(50), server_default="analyst"),
        sa.Column("is_active", sa.Boolean, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "programs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "scope_items",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE")),
        sa.Column("scope_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("is_allowed", sa.Boolean, server_default=sa.true()),
        sa.Column("notes", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE")),
        sa.Column("asset_type", sa.String(50), server_default="web"),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("port", sa.Integer),
        sa.Column("scheme", sa.String(16)),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("technologies", sa.Text),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE")),
        sa.Column("job_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), server_default="queued"),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("dry_run", sa.Boolean, server_default=sa.true()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("logs", sa.Text),
        sa.Column("error_message", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE")),
        sa.Column("asset_id", sa.Integer, sa.ForeignKey("assets.id", ondelete="SET NULL")),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("severity", sa.String(20), server_default="info"),
        sa.Column("confidence", sa.String(20), server_default="low"),
        sa.Column("status", sa.String(30), server_default="new"),
        sa.Column("category", sa.String(128)),
        sa.Column("cwe", sa.String(64)),
        sa.Column("owasp", sa.String(64)),
        sa.Column("evidence_summary", sa.Text),
        sa.Column("impact", sa.Text),
        sa.Column("remediation", sa.Text),
        sa.Column("scanner_name", sa.String(64)),
        sa.Column("raw_output", sa.Text),
        sa.Column("ai_summary", sa.Text),
        sa.Column("duplicate_of", sa.Integer, sa.ForeignKey("findings.id", ondelete="SET NULL")),
        sa.Column("manual_review_required", sa.Boolean, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id", ondelete="CASCADE")),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("content_type", sa.String(128)),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE")),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id", ondelete="CASCADE")),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("content_markdown", sa.Text, nullable=False),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "retest_tasks",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id", ondelete="CASCADE")),
        sa.Column("status", sa.String(30), server_default="pending"),
        sa.Column("result", sa.Text),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("actor", sa.String(255), server_default="system"),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("target", sa.String(512)),
        sa.Column("decision", sa.String(32), server_default="info"),
        sa.Column("detail", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "system_settings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("key", sa.String(128), nullable=False, unique=True),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    for table in (
        "system_settings",
        "audit_logs",
        "retest_tasks",
        "reports",
        "evidence",
        "findings",
        "scan_jobs",
        "assets",
        "scope_items",
        "programs",
        "users",
    ):
        op.drop_table(table)
