"""changeset batches: traffic proof before / after; job kind "proof"

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = "kind IN ('collect','analyze','batch','rollback','audit_verify')"
NEW_KINDS = "kind IN ('collect','analyze','batch','rollback','audit_verify','proof')"


def upgrade() -> None:
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    op.add_column("changeset_batches", sa.Column("proof", jsonb, nullable=True))
    op.add_column("changeset_batches", sa.Column("proof_after", jsonb, nullable=True))
    op.add_column(
        "changeset_batches", sa.Column("changes_acknowledged_by", sa.String(64), nullable=True)
    )
    op.drop_constraint(op.f("ck_job_runs_kind_known"), "job_runs", type_="check")
    op.create_check_constraint(op.f("ck_job_runs_kind_known"), "job_runs", NEW_KINDS)


def downgrade() -> None:
    op.execute("DELETE FROM job_runs WHERE kind = 'proof'")
    op.drop_constraint(op.f("ck_job_runs_kind_known"), "job_runs", type_="check")
    op.create_check_constraint(op.f("ck_job_runs_kind_known"), "job_runs", OLD_KINDS)
    op.drop_column("changeset_batches", "changes_acknowledged_by")
    op.drop_column("changeset_batches", "proof_after")
    op.drop_column("changeset_batches", "proof")
