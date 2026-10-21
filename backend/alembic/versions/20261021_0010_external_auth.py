"""external sign-in: users may come from LDAP or TACACS+

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _providers(values: str) -> None:
    # The initial migration's name went through the naming convention; find it in the catalog.
    current = op.get_bind().scalar(
        sa.text(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'users'::regclass "
            "AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%auth_provider%'"
        )
    )
    if current is not None:
        op.drop_constraint(op.f(str(current)), "users", type_="check")
    op.create_check_constraint(
        op.f("ck_users_auth_provider_known"), "users", f"auth_provider IN ({values})"
    )


def upgrade() -> None:
    _providers("'local','ldap','tacacs'")


def downgrade() -> None:
    # Never delete accounts silently: remove or convert directory accounts first.
    external = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM users WHERE auth_provider <> 'local'")
    )
    if external:
        raise RuntimeError(f"{external} LDAP / TACACS+ account(s) exist; remove them first")
    _providers("'local'")
