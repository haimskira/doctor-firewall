"""runtime routes: dynamic routes from the device routing table (B-001)

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _kinds(values: str) -> None:
    # Created by 0002 through the naming convention: look the name up instead of guessing.
    current = op.get_bind().scalar(
        sa.text(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'routes'::regclass "
            "AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%kind%'"
        )
    )
    if current is not None:
        op.drop_constraint(op.f(str(current)), "routes", type_="check")
    op.create_check_constraint(op.f("ck_routes_kind_known"), "routes", f"kind IN ({values})")


def upgrade() -> None:
    op.add_column(
        "routes",
        sa.Column("protocol", sa.String(length=16), server_default="", nullable=False),
    )
    op.add_column("routes", sa.Column("distance", sa.Integer(), nullable=True))
    _kinds("'static','connected','dynamic'")


def downgrade() -> None:
    op.execute("DELETE FROM routes WHERE kind = 'dynamic'")  # derived data, re-collected
    _kinds("'static','connected'")
    op.drop_column("routes", "distance")
    op.drop_column("routes", "protocol")
