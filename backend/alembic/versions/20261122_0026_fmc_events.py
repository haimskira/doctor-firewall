"""fmc events: the FMC integration log (requests, operation failures)

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fmc_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("op_id", sa.String(32), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("connection_id", sa.Integer(), nullable=True),
        sa.Column("connection_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("snapshot_id", sa.Integer(), nullable=True),
        sa.Column("batch_id", sa.Integer(), nullable=True),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("step", sa.String(256), nullable=False, server_default=""),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("method", sa.String(8), nullable=False, server_default=""),
        sa.Column("path", sa.String(512), nullable=False, server_default=""),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=False, server_default=""),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("response", sa.Text(), nullable=False, server_default=""),
        sa.CheckConstraint(
            "operation IN ('test','collect','batch','revert','rollback','watch')",
            name="ck_fmc_events_operation_known",
        ),
        sa.CheckConstraint(
            "kind IN ('started','request','failed','finished')", name="ck_fmc_events_kind_known"
        ),
        sa.CheckConstraint("outcome IN ('ok','error')", name="ck_fmc_events_outcome_known"),
    )
    for column in ("at", "op_id", "connection_id", "snapshot_id", "batch_id", "run_id"):
        op.create_index(f"ix_fmc_events_{column}", "fmc_events", [column])


def downgrade() -> None:
    for column in ("at", "op_id", "connection_id", "snapshot_id", "batch_id", "run_id"):
        op.drop_index(f"ix_fmc_events_{column}", table_name="fmc_events")
    op.drop_table("fmc_events")
