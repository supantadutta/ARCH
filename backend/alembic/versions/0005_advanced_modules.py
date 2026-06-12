"""advanced authorized bug-hunting module tables

Revision ID: 0005_advanced_modules
Revises: 0004_evidence_validation
Create Date: 2026-06-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_advanced_modules"
down_revision = "0004_evidence_validation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "test_accounts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("role", sa.String(64), server_default="user"),
        sa.Column("username", sa.String(255)),
        sa.Column("encrypted_secret", sa.Text),
        sa.Column("login_url", sa.String(512)),
        sa.Column("encrypted_session", sa.Text),
        sa.Column("is_authorized", sa.Boolean, server_default=sa.false()),
        sa.Column("notes", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "api_endpoints",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("method", sa.String(10), server_default="GET"),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("source", sa.String(32), server_default="manual"),
        sa.Column("object_id_params", sa.Text),
        sa.Column("auth_required", sa.String(16), server_default="unknown"),
        sa.Column("tags", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "permission_rules",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(512), nullable=False),
        sa.Column("action", sa.String(16), server_default="GET"),
        sa.Column("expected_access", sa.String(16), server_default="deny"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "workflow_definitions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(64), server_default="custom"),
        sa.Column("steps", sa.Text, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "checklists",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("kind", sa.String(64), server_default="business_logic"),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("content_markdown", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "source_routes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("method", sa.String(10), server_default="GET"),
        sa.Column("route_path", sa.String(1024), nullable=False),
        sa.Column("has_authentication", sa.Boolean, server_default=sa.false()),
        sa.Column("has_authorization", sa.Boolean, server_default=sa.false()),
        sa.Column("middleware", sa.Text),
        sa.Column("mapped_endpoint_id", sa.Integer, sa.ForeignKey("api_endpoints.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    for t in (
        "source_routes", "checklists", "workflow_definitions",
        "permission_rules", "api_endpoints", "test_accounts",
    ):
        op.drop_table(t)
