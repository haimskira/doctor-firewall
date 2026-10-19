"""Application settings.

Every value comes from the environment (prefix ``DF_``). Secrets are never passed
as environment values: the environment only names a *file* (a Docker secret) and
the value is read from that file on demand, so it never appears in ``docker
inspect``, process listings or crash dumps of the settings object.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecretFileError(RuntimeError):
    """A required secret file is missing, unreadable or empty."""


def read_secret_file(path: Path) -> str:
    """Return the content of a secret file with surrounding whitespace removed.

    The error message names the file but never includes any of its content.
    """
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SecretFileError(f"cannot read secret file {path}") from exc
    if not value:
        raise SecretFileError(f"secret file {path} is empty")
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DF_", extra="ignore", frozen=True)

    environment: Literal["prod", "dev", "test"] = "prod"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # PostgreSQL. The runtime role (df_app) cannot alter schema or rewrite audit rows.
    db_host: str = "postgres"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "doctor_firewall"
    db_user: str = "df_app"
    db_password_file: Path = Path("/run/secrets/db_app_password")

    # Redis (sessions, job queues, locks, rate-limit buckets).
    redis_host: str = "redis"
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_db: int = Field(default=0, ge=0, le=15)
    redis_password_file: Path = Path("/run/secrets/redis_password")

    # Master keyring (AES-GCM for stored credentials, HMAC for the audit chain).
    keyring_file: Path = Path("/run/secrets/master_keyring")

    # Internal trust store used to verify the FMC certificate. Verification is
    # always on; there is deliberately no setting to disable it.
    fmc_ca_bundle: Path = Path("/etc/doctor-firewall/trust/fmc-ca.pem")
    fmc_timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    # Sessions.
    session_idle_minutes: int = Field(default=30, ge=5, le=240)
    session_absolute_hours: int = Field(default=8, ge=1, le=24)

    # Brute-force protection for local login.
    login_max_failures: int = Field(default=5, ge=3, le=20)
    login_lockout_minutes: int = Field(default=15, ge=1, le=1440)

    # Request body cap enforced by the API in addition to nginx.
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=50_000_000)

    @property
    def is_dev(self) -> bool:
        return self.environment == "dev"

    def db_password(self) -> str:
        return read_secret_file(self.db_password_file)

    def redis_password(self) -> str:
        return read_secret_file(self.redis_password_file)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
