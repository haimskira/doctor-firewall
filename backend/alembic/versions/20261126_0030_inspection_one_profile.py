"""recommendations: separate file-policy kind; one organisation inspection profile

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS_0027 = (
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
    "fastpath_candidate",
)
KINDS_0030 = (*KINDS_0027, "add_file_policy")
TIERS_0027 = ("CORE", "GOLD", "SILVER", "BRONZE")
TIERS_0030 = ("ALL",)


def _check(table: str, name: str, column: str, values: Sequence[str]) -> None:
    op.drop_constraint(op.f(f"ck_{table}_{name}"), table, type_="check")
    op.create_check_constraint(
        op.f(f"ck_{table}_{name}"),
        table,
        f"{column} IN (" + ",".join(f"'{v}'" for v in values) + ")",
    )


def upgrade() -> None:
    _check("recommendations", "kind_known", "kind", KINDS_0030)
    # One profile for the whole organisation: the GOLD tier's choice (the strictest) becomes it,
    # the other per-tier rows go.
    op.drop_constraint(
        op.f("ck_inspection_profiles_tier_known"), "inspection_profiles", type_="check"
    )
    op.execute(sa.text("DELETE FROM inspection_profiles WHERE tier <> 'GOLD'"))
    op.execute(sa.text("UPDATE inspection_profiles SET tier = 'ALL' WHERE tier = 'GOLD'"))
    op.create_check_constraint(
        op.f("ck_inspection_profiles_tier_known"),
        "inspection_profiles",
        "tier IN (" + ",".join(f"'{v}'" for v in TIERS_0030) + ")",
    )


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM recommendations WHERE kind = 'add_file_policy'"))
    _check("recommendations", "kind_known", "kind", KINDS_0027)
    op.drop_constraint(
        op.f("ck_inspection_profiles_tier_known"), "inspection_profiles", type_="check"
    )
    op.execute(sa.text("UPDATE inspection_profiles SET tier = 'GOLD' WHERE tier = 'ALL'"))
    op.create_check_constraint(
        op.f("ck_inspection_profiles_tier_known"),
        "inspection_profiles",
        "tier IN (" + ",".join(f"'{v}'" for v in TIERS_0027) + ")",
    )
