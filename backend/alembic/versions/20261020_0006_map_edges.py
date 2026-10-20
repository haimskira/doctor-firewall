"""connectivity map edges

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "map_edges",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("policy_fmc_id", sa.String(length=64), nullable=False),
        sa.Column("src_node", sa.String(length=200), nullable=False),
        sa.Column("dst_node", sa.String(length=200), nullable=False),
        sa.Column("rule_count", sa.Integer(), nullable=False),
        sa.Column("hits", sa.BigInteger(), nullable=False),
        sa.Column("min_score", sa.Integer(), nullable=True),
        sa.Column("risk", sa.String(length=8), nullable=False),
        sa.Column("reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("services", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "risk IN ('green','yellow','red')", name=op.f("ck_map_edges_risk_known")
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["snapshots.id"],
            name=op.f("fk_map_edges_snapshot_id_snapshots"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_map_edges")),
    )
    op.create_index("ix_map_edges_snapshot", "map_edges", ["snapshot_id", "policy_fmc_id"])


def downgrade() -> None:
    op.drop_index("ix_map_edges_snapshot", table_name="map_edges")
    op.drop_table("map_edges")
