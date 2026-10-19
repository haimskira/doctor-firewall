"""Database engine and session factory.

All database access goes through the SQLAlchemy ORM / Core expression API, which
always sends bound parameters. Building SQL from strings is forbidden in this
codebase (enforced by ruff S608 and review).
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import URL, Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.singleton import singleton


def database_url(
    settings: Settings, *, user: str | None = None, password: str | None = None
) -> URL:
    # URL.create escapes every component; nothing is concatenated into a DSN string.
    return URL.create(
        "postgresql+psycopg",
        username=user or settings.db_user,
        password=password if password is not None else settings.db_password(),
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def make_engine(settings: Settings) -> Engine:
    return create_engine(
        database_url(settings),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        hide_parameters=True,  # never echo bound values (could be secrets) in errors
        connect_args={"application_name": "doctor-firewall", "connect_timeout": 10},
    )


@singleton
def get_engine() -> Engine:
    return make_engine(get_settings())


@singleton
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back on error."""
    session = get_sessionmaker()()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
