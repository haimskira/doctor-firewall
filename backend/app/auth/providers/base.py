"""Authentication provider abstraction.

A provider only answers "are these credentials valid, and for which username?".
Roles always come from the local ``users`` table, so adding TACACS+ or LDAP later is
a new provider class plus configuration — RBAC is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class AuthenticatedIdentity:
    user_id: int
    username: str


class AuthProvider(Protocol):
    name: str

    def authenticate(
        self, session: Session, username: str, password: str
    ) -> AuthenticatedIdentity | None:
        """Return the identity on success, ``None`` on any failure (never raise for bad creds)."""
        ...
