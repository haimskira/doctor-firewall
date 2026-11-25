"""job runs: a cancelled status

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-25
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES_0017 = ("queued", "running", "done", "failed")
STATUSES_0028 = (*STATUSES_0017, "cancelled")


def _status(values: Sequence[str]) -> None:
    op.drop_constraint(op.f("ck_job_runs_status_known"), "job_runs", type_="check")
    op.create_check_constraint(
        op.f("ck_job_runs_status_known"),
        "job_runs",
        "status IN (" + ",".join(f"'{v}'" for v in values) + ")",
    )


def upgrade() -> None:
    _status(STATUSES_0028)


def downgrade() -> None:
    op.execute("UPDATE job_runs SET status = 'failed' WHERE status = 'cancelled'")
    _status(STATUSES_0017)
