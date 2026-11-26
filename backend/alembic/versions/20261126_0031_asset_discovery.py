"""asset discovery: segments and their roles, domains, suggested (unconfirmed) assets

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = (
    "dc_servers",
    "sda_users",
    "legacy_users",
    "vc_sda",
    "vc_legacy",
    "network_devices",
    "management",
    "dmz",
    "outside",
    "unknown",
)


def _updated() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "segments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("network", sa.String(length=96), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("role", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("domain", sa.String(length=64), nullable=True),
        sa.Column("cluster", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("interface", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("zone", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("gateway", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("in_dc", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="manual"),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="100"),
        sa.Column(
            "evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("notes", sa.String(length=512), nullable=False, server_default=""),
        *_updated(),
        sa.CheckConstraint(
            "role IN (" + ",".join(f"'{r}'" for r in ROLES) + ")",
            name=op.f("ck_segments_role_known"),
        ),
        sa.CheckConstraint(
            "source IN ('manual','discovery')", name=op.f("ck_segments_source_known")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_segments")),
        sa.UniqueConstraint("network", name=op.f("uq_segments_network")),
    )
    op.create_table(
        "asset_domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="manual"),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        *_updated(),
        sa.CheckConstraint(
            "source IN ('manual','discovery')", name=op.f("ck_asset_domains_source_known")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_domains")),
        sa.UniqueConstraint("name", name=op.f("uq_asset_domains_name")),
    )
    op.add_column(
        "asset_groups",
        sa.Column("source", sa.String(length=16), nullable=False, server_default="manual"),
    )
    op.add_column(
        "asset_groups",
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column("asset_groups", sa.Column("domain", sa.String(length=64), nullable=True))
    op.add_column(
        "asset_groups",
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="100"),
    )
    op.add_column(
        "asset_groups",
        sa.Column(
            "evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
    )
    op.create_check_constraint(
        op.f("ck_asset_groups_source_known"),
        "asset_groups",
        "source IN ('manual','csv','discovery')",
    )
    op.drop_constraint(op.f("ck_assets_source_known"), "assets", type_="check")
    op.create_check_constraint(
        op.f("ck_assets_source_known"),
        "assets",
        "source IN ('manual','csv','bootstrap','discovery')",
    )


def downgrade() -> None:
    op.execute("DELETE FROM assets WHERE source = 'discovery'")
    op.execute("DELETE FROM asset_groups WHERE source = 'discovery'")
    op.drop_constraint(op.f("ck_assets_source_known"), "assets", type_="check")
    op.create_check_constraint(
        op.f("ck_assets_source_known"), "assets", "source IN ('manual','csv','bootstrap')"
    )
    op.drop_constraint(op.f("ck_asset_groups_source_known"), "asset_groups", type_="check")
    for column in ("evidence", "confidence", "domain", "confirmed", "source"):
        op.drop_column("asset_groups", column)
    op.drop_table("asset_domains")
    op.drop_table("segments")
