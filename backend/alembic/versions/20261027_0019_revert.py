"""changeset batches: status "reverted"; job kind "revert"

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-27
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BATCH = "'pending','approved','running','deployed','failed','rolled_back','cancelled'"
KINDS = "'collect','analyze','batch','rollback','audit_verify','proof'"


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_changeset_batches_status_known"), "changeset_batches", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_changeset_batches_status_known"),
        "changeset_batches",
        f"status IN ({BATCH},'reverted')",
    )
    op.drop_constraint(op.f("ck_job_runs_kind_known"), "job_runs", type_="check")
    op.create_check_constraint(
        op.f("ck_job_runs_kind_known"), "job_runs", f"kind IN ({KINDS},'revert')"
    )


def downgrade() -> None:
    op.execute("UPDATE changeset_batches SET status = 'deployed' WHERE status = 'reverted'")
    op.execute("DELETE FROM job_runs WHERE kind = 'revert'")
    op.drop_constraint(op.f("ck_job_runs_kind_known"), "job_runs", type_="check")
    op.create_check_constraint(op.f("ck_job_runs_kind_known"), "job_runs", f"kind IN ({KINDS})")
    op.drop_constraint(
        op.f("ck_changeset_batches_status_known"), "changeset_batches", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_changeset_batches_status_known"), "changeset_batches", f"status IN ({BATCH})"
    )
