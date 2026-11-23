"""recommendations: fastpath candidates; inspection profile for CORE

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS_0021 = (
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
    "add_inspection",
    "ssl_exempt_core",
    "ssl_decrypt_inbound",
    "remove_redundant_reference",
    "remove_redundant_member",
    "remove_disabled_rule",
    "compact_group",
)
KINDS_0027 = (*KINDS_0021, "fastpath_candidate")
TIERS_0009 = ("GOLD", "SILVER", "BRONZE")
TIERS_0027 = ("CORE", *TIERS_0009)


def _check(table: str, name: str, column: str, values: Sequence[str]) -> None:
    op.drop_constraint(op.f(f"ck_{table}_{name}"), table, type_="check")
    op.create_check_constraint(
        op.f(f"ck_{table}_{name}"),
        table,
        f"{column} IN (" + ",".join(f"'{v}'" for v in values) + ")",
    )


def upgrade() -> None:
    _check("recommendations", "kind_known", "kind", KINDS_0027)
    _check("inspection_profiles", "tier_known", "tier", TIERS_0027)


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM recommendations WHERE kind = 'fastpath_candidate'"))
    op.execute(sa.text("DELETE FROM inspection_profiles WHERE tier = 'CORE'"))
    _check("recommendations", "kind_known", "kind", KINDS_0021)
    _check("inspection_profiles", "tier_known", "tier", TIERS_0009)
