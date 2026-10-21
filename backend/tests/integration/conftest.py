"""Integration fixtures: real PostgreSQL, Redis and the FMC mock (TLS) from docker-compose.ci.yml.

These tests run only inside the CI stack (``DF_INTEGRATION=1``). Anywhere else
they are skipped explicitly, never silently passed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text

from app.auth.passwords import hash_password
from app.core.config import get_settings, read_secret_file
from app.db.session import database_url, get_engine, get_sessionmaker
from app.main import create_app
from app.models.user import User
from app.runtime import get_keyring, get_redis

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "Integration-Pass-42"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    run = os.environ.get("DF_INTEGRATION") == "1"
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
            if not run:
                item.add_marker(pytest.mark.skip(reason="integration stack not available"))


def _clear_caches() -> None:
    """Reset process singletons, closing pooled connections instead of leaking them."""
    if get_engine.is_initialized:
        get_engine().dispose()
    if get_redis.is_initialized:
        get_redis().close()
    for fn in (get_settings, get_engine, get_sessionmaker, get_redis, get_keyring):
        fn.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def writable_keyring(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Use a private copy of the keyring so rotation tests can add keys, as operators would.

    Retired keys stay in the file (as the rotation procedure requires), so audit rows
    signed during rotation tests remain verifiable for the rest of the session.
    """
    source = Path(os.environ["DF_KEYRING_FILE"])
    copy = tmp_path_factory.mktemp("keyring") / "master_keyring"
    copy.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    previous = os.environ["DF_KEYRING_FILE"]
    os.environ["DF_KEYRING_FILE"] = str(copy)
    _clear_caches()
    yield copy
    os.environ["DF_KEYRING_FILE"] = previous


@pytest.fixture(scope="session")
def owner_engine() -> Iterator[Engine]:
    _clear_caches()
    settings = get_settings()
    password = read_secret_file(Path(os.environ["DF_MIGRATION_DB_PASSWORD_FILE"]))
    engine = create_engine(
        database_url(settings, user=os.environ["DF_MIGRATION_DB_USER"], password=password)
    )
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    command.upgrade(cfg, "head")
    yield engine
    engine.dispose()


@pytest.fixture
def clean(owner_engine: Engine) -> None:
    _clear_caches()
    with owner_engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE users, fmc_connections, assets, asset_groups, cluster_settings, "
                "recommendation_decisions, naming_conventions RESTART IDENTITY CASCADE"
            )
        )
    redis = get_redis()
    for key in redis.scan_iter("df:*"):
        redis.delete(key)
    for key in redis.scan_iter("rq:*"):
        redis.delete(key)


@pytest.fixture
def client(clean: None) -> Iterator[TestClient]:
    with TestClient(create_app(), base_url="https://testserver") as c:
        yield c


def make_user(
    username: str,
    roles: list[str],
    *,
    password: str = PASSWORD,
    must_change: bool = False,
    active: bool = True,
) -> int:
    with get_sessionmaker()() as session:
        user = User(
            username=username,
            display_name=username.title(),
            auth_provider="local",
            password_hash=hash_password(password),
            roles=roles,
            is_active=active,
            must_change_password=must_change,
            language="he",
        )
        session.add(user)
        session.commit()
        return user.id


def login(client: TestClient, username: str, password: str = PASSWORD) -> str:
    """Log in and return the CSRF token; the session cookie stays in the client jar."""
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token: str = resp.json()["csrf_token"]
    return token
