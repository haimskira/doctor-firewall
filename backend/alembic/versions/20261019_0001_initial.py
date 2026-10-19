"""initial schema: users, fmc_connections, append-only audit_log

Revision ID: 0001
Revises:
Create Date: 2026-10-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Runtime DB role (created by infra/postgres/init); it gets DML via default privileges.


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("auth_provider", sa.String(16), nullable=False, server_default="local"),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("roles", postgresql.ARRAY(sa.String(16)), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("language", sa.String(2), nullable=False, server_default="he"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("password_changed_at", sa.DateTime(timezone=True)),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("username = lower(username)", name="ck_users_username_lowercase"),
        sa.CheckConstraint(
            "roles <@ ARRAY['viewer','optimizer','approver','admin']::varchar[]",
            name="ck_users_roles_known",
        ),
        sa.CheckConstraint("language IN ('he','en')", name="ck_users_language_known"),
        sa.CheckConstraint("auth_provider IN ('local')", name="ck_users_auth_provider_known"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )

    op.create_table(
        "fmc_connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password_enc", sa.Text(), nullable=False),
        sa.Column("domain_uuid", sa.String(36)),
        sa.Column("server_version", sa.String(128)),
        sa.Column("last_test_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_ok", sa.Boolean()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_fmc_connections_port_range"),
        sa.PrimaryKeyConstraint("id", name="pk_fmc_connections"),
        sa.UniqueConstraint("name", name="uq_fmc_connections_name"),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.BigInteger()),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("cluster", sa.String(128)),
        sa.Column("target", sa.String(256)),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("key_id", sa.String(32), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('success','failure','denied')", name="ck_audit_log_outcome_known"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
        sa.UniqueConstraint("record_hash", name="uq_audit_log_record_hash"),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    # ---- append-only enforcement, independent of application code ----
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM df_app")
    op.execute(
        """
        CREATE FUNCTION audit_log_reject_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change()"
    )
    op.execute(
        "CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change()"
    )
    # The runtime role may read but never alter migration state.
    op.execute("REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM df_app")


def downgrade() -> None:
    raise RuntimeError("downgrading the initial schema would destroy the audit trail")
