"""inspection: phase-6 recommendation kinds and the tier -> inspection profile mapping

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS_0005 = (
    "remove_shadowed_rule",
    "remove_dead_rule",
    "remove_unused_object",
    "merge_duplicate_objects",
    "merge_groups",
    "split_group",
    "split_rule",
    "merge_rules",
    "tighten_source",
    "tighten_ports",
    "rename_role",
    "rename_convention",
    "literal_to_object",
)
KINDS_0009 = (*KINDS_0005, "add_inspection", "ssl_exempt_core", "ssl_decrypt_inbound")


def _kind_check(kinds: Sequence[str]) -> None:
    op.drop_constraint(op.f("ck_recommendations_kind_known"), "recommendations", type_="check")
    op.create_check_constraint(
        op.f("ck_recommendations_kind_known"),
        "recommendations",
        "kind IN (" + ",".join(f"'{k}'" for k in kinds) + ")",
    )


def upgrade() -> None:
    _kind_check(KINDS_0009)
    op.create_table(
        "inspection_profiles",
        sa.Column("tier", sa.String(length=8), nullable=False),
        sa.Column("ips_policy", sa.String(length=256), nullable=True),
        sa.Column("file_policy", sa.String(length=256), nullable=True),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "tier IN ('GOLD','SILVER','BRONZE')", name=op.f("ck_inspection_profiles_tier_known")
        ),
        sa.PrimaryKeyConstraint("tier", name=op.f("pk_inspection_profiles")),
    )


def downgrade() -> None:
    op.drop_table("inspection_profiles")
    op.execute(
        sa.text(
            "DELETE FROM recommendations WHERE kind IN "
            "('add_inspection','ssl_exempt_core','ssl_decrypt_inbound')"
        )
    )
    _kind_check(KINDS_0005)
