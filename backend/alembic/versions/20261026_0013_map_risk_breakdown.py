"""map edges: rules and hits per risk colour (for flow views)

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for name in ("risk_rules", "risk_hits"):
        op.add_column(
            "map_edges",
            sa.Column(
                name,
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
        )


def downgrade() -> None:
    op.drop_column("map_edges", "risk_hits")
    op.drop_column("map_edges", "risk_rules")
