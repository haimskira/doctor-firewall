"""Shared types for external sign-in providers (LDAP, TACACS+).

An external provider verifies the password against the directory and may return the roles
the directory grants (``roles is None``: the directory does not manage roles; the local user
record keeps them). It never raises for wrong credentials; an unreachable or misconfigured
directory raises :class:`ProviderUnavailableError` so the failure is audited as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ProviderUnavailableError(RuntimeError):
    """The directory cannot be reached or answered unexpectedly (never contains secrets)."""


@dataclass(frozen=True)
class ExternalIdentity:
    username: str
    display_name: str
    roles: frozenset[str] | None


class ExternalProvider(Protocol):
    name: str

    def verify(self, username: str, password: str) -> ExternalIdentity | None:
        """The identity on valid credentials, ``None`` on invalid ones."""
        ...
