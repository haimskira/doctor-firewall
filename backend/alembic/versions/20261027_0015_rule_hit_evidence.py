"""rules: evidence behind hit counts (last change, deployment)

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("rules", sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("rules", sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "rules",
        sa.Column("never_deployed", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("rules", "never_deployed")
    op.drop_column("rules", "deployed_at")
    op.drop_column("rules", "modified_at")
