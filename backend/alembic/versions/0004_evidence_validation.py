"""evidence-based validation state on findings

Revision ID: 0004_evidence_validation
Revises: 0003_auth_rbac_sla
Create Date: 2026-06-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_evidence_validation"
down_revision = "0003_auth_rbac_sla"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("validation_state", sa.String(32), server_default="unvalidated", nullable=False),
    )
    op.add_column("findings", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "validated_at")
    op.drop_column("findings", "validation_state")
