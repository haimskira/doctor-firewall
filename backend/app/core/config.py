"""Application settings.

Every value comes from the environment (prefix ``DF_``). Secrets are never passed
as environment values: the environment only names a *file* (a Docker secret) and
the value is read from that file on demand, so it never appears in ``docker
inspect``, process listings or crash dumps of the settings object.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AUTH_PROVIDERS = ("local", "ldap", "tacacs")
ROLES = ("viewer", "optimizer", "approver", "admin")
_LDAP_FILTER = re.compile(r"^\(.*\{username\}.*\)$")


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
    # Client-side throttling towards the FMC (hard limits: 300 GET/min, 10 connections).
    fmc_requests_per_minute: int = Field(default=240, ge=10, le=290)
    fmc_concurrency: int = Field(default=4, ge=1, le=8)

    # Snapshots.
    snapshot_retention: int = Field(default=10, ge=2, le=500)
    collect_stale_minutes: int = Field(default=15, ge=5, le=240)
    collect_job_timeout_seconds: int = Field(default=6 * 3600, ge=600, le=48 * 3600)

    # Analysis. Platform limits are per cluster (cluster_settings); these are the
    # defaults used until an operator sets and verifies them.
    default_ace_limit: int = Field(default=1_000_000, ge=1000)
    default_deploy_change_limit: int = Field(default=100, ge=1, le=100_000)
    dead_rule_days: int = Field(default=90, ge=7, le=3650)

    # Enforcement (phase 5): deploy polling and the cross-worker FMC write lock.
    deploy_poll_seconds: float = Field(default=10.0, ge=0.0, le=300.0)
    deploy_timeout_seconds: int = Field(default=1800, ge=60, le=6 * 3600)
    write_lock_ttl_seconds: int = Field(default=2 * 3600, ge=300, le=24 * 3600)

    # Sessions.
    session_idle_minutes: int = Field(default=30, ge=5, le=240)
    session_absolute_hours: int = Field(default=8, ge=1, le=24)

    # Sign-in providers, in the order tried for a username not yet known locally.
    # "local" always works for existing local accounts (break-glass administrator).
    auth_providers: str = Field(default="local", pattern=r"^[a-z]+(,[a-z]+)*$")

    # LDAP / Active Directory (LDAPS or StartTLS only; certificate verified against ldap_ca_file).
    ldap_url: str = ""
    ldap_start_tls: bool = False
    ldap_ca_file: Path = Path("/etc/doctor-firewall/trust/ldap-ca.pem")
    ldap_bind_dn: str = ""
    ldap_bind_password_file: Path = Path("/run/secrets/ldap_bind_password")
    ldap_user_base: str = ""
    ldap_user_filter: str = "(&(objectClass=user)(sAMAccountName={username}))"
    ldap_display_name_attribute: str = Field(default="displayName", pattern=r"^[A-Za-z0-9-]+$")
    # role=group DN pairs separated by ";" (DNs contain commas). Empty: roles stay local.
    ldap_group_roles: str = ""
    ldap_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    # TACACS+ (e.g. Cisco ISE), RFC 8907. Roles from an authorization attribute.
    tacacs_host: str = ""
    tacacs_port: int = Field(default=49, ge=1, le=65535)
    tacacs_secret_file: Path = Path("/run/secrets/tacacs_secret")
    tacacs_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    tacacs_service: str = Field(default="shell", pattern=r"^[A-Za-z0-9_-]{1,32}$")
    # Attribute carrying the roles (e.g. "df-role=optimizer,approver"). Empty: roles stay local.
    tacacs_role_attribute: str = Field(default="df-role", pattern=r"^([A-Za-z0-9_-]{1,32})?$")

    # Brute-force protection for local login.
    login_max_failures: int = Field(default=5, ge=3, le=20)
    login_lockout_minutes: int = Field(default=15, ge=1, le=1440)

    # Request body cap enforced by the API in addition to nginx.
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=50_000_000)

    @property
    def is_dev(self) -> bool:
        return self.environment == "dev"

    @property
    def providers(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self.auth_providers.split(",")))

    @property
    def ldap_role_groups(self) -> dict[str, frozenset[str]]:
        """role -> group DNs (normalised: lower case, no spaces around separators)."""
        out: dict[str, set[str]] = {}
        for item in self.ldap_group_roles.split(";"):
            if not item.strip():
                continue
            role, _, dn = item.partition("=")
            out.setdefault(role.strip(), set()).add(normalise_dn(dn))
        return {role: frozenset(dns) for role, dns in out.items()}

    @model_validator(mode="after")
    def _auth_config(self) -> Self:
        unknown = set(self.providers) - set(AUTH_PROVIDERS)
        if unknown:
            raise ValueError(f"unknown auth provider(s): {', '.join(sorted(unknown))}")
        if "ldap" in self.providers:
            url = urlsplit(self.ldap_url)
            if url.scheme not in ("ldaps", "ldap") or not url.hostname:
                raise ValueError(
                    "DF_LDAP_URL must be ldaps://host[:port] (or ldap:// with StartTLS)"
                )
            if url.scheme == "ldap" and not self.ldap_start_tls:
                raise ValueError("plain LDAP is refused: use ldaps:// or DF_LDAP_START_TLS=true")
            if not self.ldap_user_base or not self.ldap_bind_dn:
                raise ValueError("DF_LDAP_USER_BASE and DF_LDAP_BIND_DN are required for LDAP")
            if not _LDAP_FILTER.fullmatch(self.ldap_user_filter):
                raise ValueError("DF_LDAP_USER_FILTER must be an LDAP filter containing {username}")
            for item in self.ldap_group_roles.split(";"):
                if item.strip():
                    role, sep, dn = item.partition("=")
                    if not sep or role.strip() not in ROLES or not dn.strip():
                        raise ValueError(
                            "DF_LDAP_GROUP_ROLES: role=<group DN>;... with known roles"
                        )
        if "tacacs" in self.providers and not self.tacacs_host:
            raise ValueError("DF_TACACS_HOST is required for TACACS+")
        return self

    def db_password(self) -> str:
        return read_secret_file(self.db_password_file)

    def redis_password(self) -> str:
        return read_secret_file(self.redis_password_file)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def normalise_dn(dn: str) -> str:
    """Case-insensitive, whitespace-tolerant form of a DN for comparisons."""
    return ",".join(part.strip() for part in dn.strip().lower().split(","))
