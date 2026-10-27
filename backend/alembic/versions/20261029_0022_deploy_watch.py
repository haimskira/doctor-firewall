"""deploy watches: hit counters of the rules a deployed batch touched, and of the blocks behind

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json(name: str, default: str) -> sa.Column[object]:
    return sa.Column(
        name,
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=False,
        server_default=sa.text(f"'{default}'::jsonb"),
    )


def upgrade() -> None:
    op.create_table(
        "deploy_watches",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "batch_id",
            sa.BigInteger(),
            sa.ForeignKey("changeset_batches.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="watching"),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checks", sa.Integer(), nullable=False, server_default="0"),
        _json("rules", "[]"),
        sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=True),
        _json("baseline", "{}"),
        sa.Column("last_at", sa.DateTime(timezone=True), nullable=True),
        _json("last", "{}"),
        _json("alerts", "[]"),
        sa.Column("error", sa.String(512), nullable=True),
        sa.Column("dismissed_by", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "status IN ('watching','ok','alert','dismissed','ended')",
            name=op.f("ck_deploy_watches_status_known"),
        ),
    )
    op.create_index("ix_deploy_watches_due", "deploy_watches", ["status", "next_check_at"])


def downgrade() -> None:
    op.drop_index("ix_deploy_watches_due", table_name="deploy_watches")
    op.drop_table("deploy_watches")
