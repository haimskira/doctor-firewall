"""recommendations, decisions, naming conventions

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = (
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
CONVENTION_KINDS = (
    "host",
    "network",
    "range",
    "fqdn",
    "network_group",
    "port",
    "port_group",
    "rule",
)


def _in(values: Sequence[str]) -> str:
    return ",".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.create_table(
        "recommendations",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("policy_fmc_id", sa.String(length=64), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("principle", sa.String(length=48), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("targets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("preview", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("display", sa.String(length=8), nullable=False),
        sa.Column("deploy_cost", sa.Integer(), nullable=False),
        sa.Column("ace_delta", sa.BigInteger(), nullable=False),
        sa.Column("score_delta", sa.Integer(), nullable=True),
        sa.Column("warnings", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.CheckConstraint(f"kind IN ({_in(KINDS)})", name=op.f("ck_recommendations_kind_known")),
        sa.CheckConstraint(
            "display IN ('inline','split')", name=op.f("ck_recommendations_display_known")
        ),
        sa.CheckConstraint(
            "deploy_cost >= 0", name=op.f("ck_recommendations_deploy_cost_positive")
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["snapshots.id"],
            name=op.f("fk_recommendations_snapshot_id_snapshots"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recommendations")),
    )
    op.create_index("ix_recommendations_snapshot_kind", "recommendations", ["snapshot_id", "kind"])
    op.create_index(
        "ix_recommendations_snapshot_priority", "recommendations", ["snapshot_id", "priority"]
    )
    op.create_index(op.f("ix_recommendations_fingerprint"), "recommendations", ["fingerprint"])
    op.create_table(
        "recommendation_decisions",
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.String(length=512), nullable=False),
        sa.Column("decided_by", sa.String(length=64), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('accepted','dismissed')",
            name=op.f("ck_recommendation_decisions_status_known"),
        ),
        sa.PrimaryKeyConstraint("fingerprint", name=op.f("pk_recommendation_decisions")),
    )
    op.create_table(
        "naming_conventions",
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("template", sa.String(length=128), nullable=False),
        sa.Column("letter_case", sa.String(length=8), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"kind IN ({_in(CONVENTION_KINDS)})", name=op.f("ck_naming_conventions_kind_known")
        ),
        sa.CheckConstraint(
            "letter_case IN ('upper','lower','keep')", name=op.f("ck_naming_conventions_case_known")
        ),
        sa.PrimaryKeyConstraint("kind", name=op.f("pk_naming_conventions")),
    )


def downgrade() -> None:
    op.drop_table("naming_conventions")
    op.drop_table("recommendation_decisions")
    op.drop_index(op.f("ix_recommendations_fingerprint"), table_name="recommendations")
    op.drop_index("ix_recommendations_snapshot_priority", table_name="recommendations")
    op.drop_index("ix_recommendations_snapshot_kind", table_name="recommendations")
    op.drop_table("recommendations")
