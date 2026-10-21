"""Sign-in across providers: local accounts, LDAP and TACACS+.

* A known user signs in with the provider recorded on the account (a local account always
  stays local — the break-glass administrator never depends on a directory).
* An unknown username is tried against the external providers in ``DF_AUTH_PROVIDERS`` order;
  when the directory grants roles the account is created on the spot (no local password).
* When a directory manages roles (LDAP group mapping, TACACS+ role attribute) the account's
  roles are replaced by the directory's at every sign-in; no mapped role means no access.
  Otherwise the roles an administrator assigned locally apply.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.providers.external import (
    ExternalIdentity,
    ExternalProvider,
    ProviderUnavailableError,
)
from app.auth.providers.ldap import LdapProvider
from app.auth.providers.local import LocalProvider
from app.auth.providers.tacacs import TacacsProvider
from app.core.config import Settings
from app.models.user import User

log = logging.getLogger(__name__)


@dataclass
class SignIn:
    user: User | None
    reason: str = ""  # why it failed (audit only; the client always sees invalid_credentials)
    provider: str = "local"
    details: dict[str, object] = field(default_factory=dict)


def external_provider(name: str, settings: Settings, remote: str) -> ExternalProvider:
    if name == "ldap":
        return LdapProvider(settings)
    if name == "tacacs":
        return TacacsProvider(settings, remote)
    raise ValueError(f"not an external provider: {name}")


def _verify(
    provider: ExternalProvider, username: str, password: str
) -> tuple[ExternalIdentity | None, str]:
    try:
        return provider.verify(username, password), ""
    except ProviderUnavailableError as exc:
        log.warning("auth provider unavailable", extra={"provider": provider.name})
        return None, f"provider_unavailable: {exc}"


def sign_in(
    db: Session,
    settings: Settings,
    username: str,
    password: str,
    *,
    remote: str = "",
    providers: dict[str, ExternalProvider] | None = None,
) -> SignIn:
    """Authenticate; on success the user row is up to date (roles, display name)."""

    def provider(name: str) -> ExternalProvider:
        if providers is not None and name in providers:
            return providers[name]
        return external_provider(name, settings, remote)

    user = db.scalar(select(User).where(User.username == username))
    if user is None or user.auth_provider == "local":
        if LocalProvider().authenticate(db, username, password) is not None:
            return SignIn(user)
        if user is not None:
            return SignIn(None, "invalid_credentials")
        return _first_external(db, settings, username, password, provider)

    if user.auth_provider not in settings.providers:
        return SignIn(None, "provider_disabled", user.auth_provider)
    identity, failure = _verify(provider(user.auth_provider), username, password)
    if identity is None:
        return SignIn(None, failure or "invalid_credentials", user.auth_provider)
    if not user.is_active:
        return SignIn(None, "inactive", user.auth_provider)
    details: dict[str, object] = {}
    if identity.roles is not None:
        if not identity.roles:
            return SignIn(None, "no_role", user.auth_provider)
        if set(user.roles) != identity.roles:
            details["roles"] = {"from": sorted(user.roles), "to": sorted(identity.roles)}
            user.roles = sorted(identity.roles)
    if identity.display_name and not user.display_name:
        user.display_name = identity.display_name
    return SignIn(user, provider=user.auth_provider, details=details)


def _first_external(
    db: Session,
    settings: Settings,
    username: str,
    password: str,
    provider: Callable[[str], ExternalProvider],
) -> SignIn:
    failure = "invalid_credentials"
    for name in settings.providers:
        if name == "local":
            continue
        identity, why = _verify(provider(name), username, password)
        if identity is None:
            failure = why or failure
            continue
        if identity.roles is None:
            # The directory does not manage roles: an administrator creates the account first.
            return SignIn(None, "not_provisioned", name)
        if not identity.roles:
            return SignIn(None, "no_role", name)
        user = User(
            username=username,
            display_name=identity.display_name,
            auth_provider=name,
            password_hash=None,
            roles=sorted(identity.roles),
            is_active=True,
            must_change_password=False,
            language="he",
        )
        db.add(user)
        db.flush()
        return SignIn(user, provider=name, details={"provisioned": True, "roles": user.roles})
    return SignIn(None, failure)
