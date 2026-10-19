"""Alembic environment.

Migrations run as the schema owner role (``df_owner``), never as the runtime role.
Credentials come from Docker secrets:

* ``DF_MIGRATION_DB_USER``           (default ``df_owner``)
* ``DF_MIGRATION_DB_PASSWORD_FILE``  (default ``/run/secrets/db_owner_password``)
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic import context
from sqlalchemy import URL, create_engine

import app.models  # noqa: F401  (registers tables on Base.metadata)
from app.core.config import get_settings, read_secret_file
from app.db.base import Base
from app.db.session import database_url

target_metadata = Base.metadata


def _url() -> URL:
    settings = get_settings()
    user = os.environ.get("DF_MIGRATION_DB_USER", "df_owner")
    password_file = Path(
        os.environ.get("DF_MIGRATION_DB_PASSWORD_FILE", "/run/secrets/db_owner_password")
    )
    return database_url(settings, user=user, password=read_secret_file(password_file))


def run_migrations_online() -> None:
    engine = create_engine(_url(), hide_parameters=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline SQL generation is not supported; run against a database")
run_migrations_online()
