"""recommendations: compact network groups

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS_0020 = (
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
)
KINDS_0021 = (*KINDS_0020, "compact_group")


def _kinds(kinds: Sequence[str]) -> None:
    op.drop_constraint(op.f("ck_recommendations_kind_known"), "recommendations", type_="check")
    op.create_check_constraint(
        op.f("ck_recommendations_kind_known"),
        "recommendations",
        "kind IN (" + ",".join(f"'{k}'" for k in kinds) + ")",
    )


def upgrade() -> None:
    _kinds(KINDS_0021)


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM recommendations WHERE kind = 'compact_group'"))
    _kinds(KINDS_0020)
