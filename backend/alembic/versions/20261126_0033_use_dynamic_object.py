"""recommendations: advisory use_dynamic_object kind

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS_0030 = (
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
    "add_file_policy",
)
KINDS_0033 = (*KINDS_0030, "use_dynamic_object")


def _check(values: Sequence[str]) -> None:
    op.drop_constraint(op.f("ck_recommendations_kind_known"), "recommendations", type_="check")
    op.create_check_constraint(
        op.f("ck_recommendations_kind_known"),
        "recommendations",
        "kind IN (" + ",".join(f"'{v}'" for v in values) + ")",
    )


def upgrade() -> None:
    _check(KINDS_0033)


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM recommendations WHERE kind = 'use_dynamic_object'"))
    _check(KINDS_0030)
