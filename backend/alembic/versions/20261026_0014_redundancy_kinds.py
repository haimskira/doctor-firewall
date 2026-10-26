"""recommendations: redundant references / members

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS_0009 = (
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
)
KINDS_0014 = (*KINDS_0009, "remove_redundant_reference", "remove_redundant_member")


def _kinds(kinds: Sequence[str]) -> None:
    op.drop_constraint(op.f("ck_recommendations_kind_known"), "recommendations", type_="check")
    op.create_check_constraint(
        op.f("ck_recommendations_kind_known"),
        "recommendations",
        "kind IN (" + ",".join(f"'{k}'" for k in kinds) + ")",
    )


def upgrade() -> None:
    _kinds(KINDS_0014)


def downgrade() -> None:
    op.execute(
        sa.text(
            "DELETE FROM recommendations WHERE kind IN "
            "('remove_redundant_reference','remove_redundant_member')"
        )
    )
    _kinds(KINDS_0009)
