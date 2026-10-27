"""job runs: queued / running / finished background jobs with their progress

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "job_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=True),
        sa.Column("batch_id", sa.BigInteger(), nullable=True),
        sa.Column("changeset_id", sa.BigInteger(), nullable=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("step", sa.String(64), nullable=False, server_default="queued"),
        sa.Column(
            "step_args",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error", sa.String(512), nullable=True),
        sa.Column("rq_job_id", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('collect','analyze','batch','rollback','audit_verify')",
            name=op.f("ck_job_runs_kind_known"),
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','done','failed')", name=op.f("ck_job_runs_status_known")
        ),
        sa.CheckConstraint("progress BETWEEN 0 AND 100", name=op.f("ck_job_runs_progress_range")),
    )
    op.create_index("ix_job_runs_status", "job_runs", ["status", "created_at"])
    op.create_index("ix_job_runs_snapshot_id", "job_runs", ["snapshot_id"])


def downgrade() -> None:
    op.drop_index("ix_job_runs_snapshot_id", table_name="job_runs")
    op.drop_index("ix_job_runs_status", table_name="job_runs")
    op.drop_table("job_runs")
