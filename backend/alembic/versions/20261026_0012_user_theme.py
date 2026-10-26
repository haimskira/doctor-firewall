"""users: colour theme preference (system / light / dark)

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("theme", sa.String(length=8), server_default="system", nullable=False),
    )
    op.create_check_constraint(
        op.f("ck_users_theme_known"), "users", "theme IN ('system','light','dark')"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_users_theme_known"), "users", type_="check")
    op.drop_column("users", "theme")
