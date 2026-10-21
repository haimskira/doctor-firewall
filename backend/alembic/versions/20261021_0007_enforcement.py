"""executable plans, changesets and batches

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CHANGESET = "'open','in_progress','completed','failed','cancelled'"
BATCH = "'pending','approved','running','deployed','failed','rolled_back','cancelled'"


def upgrade() -> None:
    op.add_column(
        "recommendations",
        sa.Column(
            "plan",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_table(
        "changesets",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("connection_id", sa.Integer(), nullable=True),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("ticket_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("deploy_limit", sa.Integer(), nullable=False),
        sa.Column("deploy_limit_verified", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(f"status IN ({CHANGESET})", name=op.f("ck_changesets_status_known")),
        sa.CheckConstraint("deploy_limit > 0", name=op.f("ck_changesets_deploy_limit_positive")),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["fmc_connections.id"],
            name=op.f("fk_changesets_connection_id_fmc_connections"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["snapshots.id"],
            name=op.f("fk_changesets_snapshot_id_snapshots"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_changesets")),
    )
    op.create_table(
        "changeset_items",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("changeset_id", sa.BigInteger(), nullable=False),
        sa.Column("batch_seq", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("policy_fmc_id", sa.String(length=64), nullable=True),
        sa.Column("plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("op_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["changeset_id"],
            ["changesets.id"],
            name=op.f("fk_changeset_items_changeset_id_changesets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_changeset_items")),
        sa.UniqueConstraint("changeset_id", "fingerprint", name="item_once"),
    )
    op.create_index(op.f("ix_changeset_items_changeset_id"), "changeset_items", ["changeset_id"])
    op.create_table(
        "changeset_batches",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("changeset_id", sa.BigInteger(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("op_count", sa.Integer(), nullable=False),
        sa.Column("deploy_limit", sa.Integer(), nullable=False),
        sa.Column("clusters", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("approved_by", sa.String(length=64), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deploy_job_id", sa.String(length=64), nullable=True),
        sa.Column("error", sa.String(length=512), nullable=True),
        sa.Column("results", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(f"status IN ({BATCH})", name=op.f("ck_changeset_batches_status_known")),
        sa.ForeignKeyConstraint(
            ["changeset_id"],
            ["changesets.id"],
            name=op.f("fk_changeset_batches_changeset_id_changesets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_changeset_batches")),
        sa.UniqueConstraint("changeset_id", "seq", name="batch_seq"),
    )
    op.create_index(
        op.f("ix_changeset_batches_changeset_id"), "changeset_batches", ["changeset_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_changeset_batches_changeset_id"), table_name="changeset_batches")
    op.drop_table("changeset_batches")
    op.drop_index(op.f("ix_changeset_items_changeset_id"), table_name="changeset_items")
    op.drop_table("changeset_items")
    op.drop_table("changesets")
    op.drop_column("recommendations", "plan")
