"""asset groups: assets (systems, servers, users, segments) with components

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-21

Existing entries become components of an asset named after their ``system`` (one asset per
system and tier; a system classified in two tiers gets the tier appended to the name).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("tier", sa.String(length=8), nullable=False),
        sa.Column("user_type", sa.String(length=16), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "tier IN ('CORE','GOLD','SILVER','BRONZE','USERS')",
            name=op.f("ck_asset_groups_tier_known"),
        ),
        sa.CheckConstraint(
            "kind IN ('system','server','user','user_segment')",
            name=op.f("ck_asset_groups_kind_known"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_groups")),
        sa.UniqueConstraint("name", name=op.f("uq_asset_groups_name")),
    )
    op.add_column("assets", sa.Column("group_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_assets_group_id_asset_groups"),
        "assets",
        "asset_groups",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(op.f("ix_assets_group_id"), "assets", ["group_id"])

    # Data: group the confirmed entries by (system, tier); suggestions stay unassigned.
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT system, tier, min(user_type) AS user_type, count(*) AS n, "
            "bool_and(network LIKE '%/32' OR network LIKE '%/128') AS hosts "
            "FROM assets WHERE confirmed GROUP BY system, tier ORDER BY system, tier"
        )
    ).all()
    tiers_per_system: dict[str, int] = {}
    for row in rows:
        tiers_per_system[row.system] = tiers_per_system.get(row.system, 0) + 1
    for row in rows:
        name = row.system if tiers_per_system[row.system] == 1 else f"{row.system} ({row.tier})"
        if row.tier == "USERS":
            kind = "user_segment"
        elif row.n == 1 and row.hosts:
            kind = "server"
        else:
            kind = "system"
        group_id = bind.execute(
            sa.text(
                "INSERT INTO asset_groups "
                "(name, kind, tier, user_type, owner, description, updated_by) "
                "VALUES (:name, :kind, :tier, :user_type, '', '', 'migration') RETURNING id"
            ),
            {"name": name[:128], "kind": kind, "tier": row.tier, "user_type": row.user_type},
        ).scalar_one()
        bind.execute(
            sa.text(
                "UPDATE assets SET group_id = :gid "
                "WHERE confirmed AND system = :system AND tier = :tier"
            ),
            {"gid": group_id, "system": row.system, "tier": row.tier},
        )


def downgrade() -> None:
    op.drop_index(op.f("ix_assets_group_id"), table_name="assets")
    op.drop_constraint(op.f("fk_assets_group_id_asset_groups"), "assets", type_="foreignkey")
    op.drop_column("assets", "group_id")
    op.drop_table("asset_groups")
