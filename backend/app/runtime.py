"""Process-wide service singletons (FastAPI dependencies; overridable in tests)."""

from __future__ import annotations

from datetime import timedelta

from redis import Redis

from app.audit.chain import AuditLog
from app.auth.sessions import SessionStore
from app.auth.throttle import LoginThrottle
from app.core.config import get_settings
from app.core.crypto import Keyring, SecretBox, load_keyring
from app.core.singleton import singleton


@singleton
def get_redis() -> Redis:
    settings = get_settings()
    return Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        password=settings.redis_password(),
        socket_timeout=5,
        socket_connect_timeout=5,
        health_check_interval=30,
    )


@singleton
def get_keyring() -> Keyring:
    return load_keyring(get_settings().keyring_file)


def get_secretbox() -> SecretBox:
    return SecretBox(get_keyring())


def get_audit() -> AuditLog:
    return AuditLog(get_keyring())


def get_session_store() -> SessionStore:
    settings = get_settings()
    return SessionStore(
        get_redis(),
        idle=timedelta(minutes=settings.session_idle_minutes),
        absolute=timedelta(hours=settings.session_absolute_hours),
    )


def get_login_throttle() -> LoginThrottle:
    settings = get_settings()
    return LoginThrottle(
        get_redis(),
        max_failures=settings.login_max_failures,
        lockout=timedelta(minutes=settings.login_lockout_minutes),
    )
