"""add scanner output columns to scan_jobs

Revision ID: 0002_scanner_outputs
Revises: 0001_initial
Create Date: 2026-06-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_scanner_outputs"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("stdout", sa.Text(), nullable=True))
    op.add_column("scan_jobs", sa.Column("stderr", sa.Text(), nullable=True))
    op.add_column("scan_jobs", sa.Column("exit_code", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_jobs", "exit_code")
    op.drop_column("scan_jobs", "stderr")
    op.drop_column("scan_jobs", "stdout")
