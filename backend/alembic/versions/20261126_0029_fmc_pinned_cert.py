"""FMC connections: a pinned server certificate (connect by IP address)

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("fmc_connections", sa.Column("pinned_cert", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("fmc_connections", "pinned_cert")
