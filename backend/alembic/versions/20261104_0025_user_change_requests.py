"""user change requests: two-administrator rule for privileged user changes

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_change_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("target_user_id", sa.Integer(), nullable=True),
        sa.Column("target_username", sa.String(64), nullable=False),
        sa.Column("payload", JSONB(), nullable=False, server_default="{}"),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column(
            "requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("decided_by", sa.String(64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('create','roles','password_reset')", name="ck_user_change_requests_kind_known"
        ),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','expired')",
            name="ck_user_change_requests_status_known",
        ),
    )
    op.create_index("ix_user_change_requests_status", "user_change_requests", ["status"])


def downgrade() -> None:
    op.drop_index("ix_user_change_requests_status", table_name="user_change_requests")
    op.drop_table("user_change_requests")
