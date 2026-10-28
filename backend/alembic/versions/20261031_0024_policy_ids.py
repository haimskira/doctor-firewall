"""policy ids: the access policies each finding and recommendation belongs to

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("findings", "recommendations")


def upgrade() -> None:
    for table in TABLES:
        op.add_column(
            table,
            sa.Column("policy_ids", ARRAY(sa.String(64)), nullable=False, server_default="{}"),
        )
        op.create_index(f"ix_{table}_policy_ids", table, ["policy_ids"], postgresql_using="gin")


def downgrade() -> None:
    for table in TABLES:
        op.drop_index(f"ix_{table}_policy_ids", table_name=table)
        op.drop_column(table, "policy_ids")
