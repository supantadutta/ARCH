"""auth, rbac membership, SLA and per-job timeout

Revision ID: 0003_auth_rbac_sla
Revises: 0002_scanner_outputs
Create Date: 2026-06-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_auth_rbac_sla"
down_revision = "0002_scanner_outputs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Users: password hash for JWT login; default role becomes "viewer".
    op.add_column("users", sa.Column("hashed_password", sa.String(255), nullable=True))

    # Program membership (per-program access control).
    op.create_table(
        "program_members",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("program_id", sa.Integer, sa.ForeignKey("programs.id", ondelete="CASCADE"), index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("program_id", "user_id", name="uq_program_member"),
    )

    # Finding SLA deadline.
    op.add_column("findings", sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True))

    # Per-job scanner timeout override.
    op.add_column("scan_jobs", sa.Column("timeout_seconds", sa.Integer, nullable=True))


def downgrade() -> None:
    op.drop_column("scan_jobs", "timeout_seconds")
    op.drop_column("findings", "sla_due_at")
    op.drop_table("program_members")
    op.drop_column("users", "hashed_password")
