"""LDAP / Active Directory sign-in.

1. bind with the service account (read-only search rights);
2. find exactly one entry for the username (the filter value is escaped);
3. bind as that entry with the user's password — the directory decides;
4. roles from the entry's groups (``memberOf``) via ``DF_LDAP_GROUP_ROLES``.

Only LDAPS or StartTLS, with the server certificate verified against ``DF_LDAP_CA_FILE``. An
empty password is refused before any bind: LDAP treats it as an *unauthenticated* bind that
succeeds without checking anything (RFC 4513 §5.1.2).
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from ldap3 import AUTO_BIND_NONE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.auth.providers.external import ExternalIdentity, ProviderUnavailableError
from app.core.config import SecretFileError, Settings, normalise_dn, read_secret_file

log = logging.getLogger(__name__)

# (user DN or None for the service account, password) -> an unbound connection
Connector = Callable[[str, str], Connection]


def tls_connector(settings: Settings) -> Connector:
    """Connections over LDAPS / StartTLS with full certificate verification."""
    url = urlsplit(settings.ldap_url)
    # Default context: TLS 1.2+, certificate and host name verified against the CA file.
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=str(settings.ldap_ca_file))
    ldaps = url.scheme == "ldaps"
    server = Server(
        url.hostname or "",
        port=url.port or (636 if ldaps else 389),
        use_ssl=ldaps,
        tls=tls,
        get_info=NONE,
        connect_timeout=settings.ldap_timeout_seconds,
    )

    def connect(user: str, password: str) -> Connection:
        conn = Connection(
            server,
            user=user,
            password=password,
            auto_bind=AUTO_BIND_NONE,
            read_only=True,
            receive_timeout=settings.ldap_timeout_seconds,
            raise_exceptions=False,
        )
        if settings.ldap_start_tls and not ldaps:
            conn.open()
            if not conn.start_tls():
                raise ProviderUnavailableError("LDAP StartTLS failed")
        return conn

    return connect


class LdapProvider:
    name = "ldap"

    def __init__(self, settings: Settings, connector: Connector | None = None) -> None:
        self.settings = settings
        self.connect = connector or tls_connector(settings)
        self.role_groups = settings.ldap_role_groups

    def _service_password(self) -> str:
        try:
            return read_secret_file(self.settings.ldap_bind_password_file)
        except SecretFileError as exc:
            raise ProviderUnavailableError("LDAP service account password not set") from exc

    def verify(self, username: str, password: str) -> ExternalIdentity | None:
        if not password:
            return None
        try:
            entry = self._find(username)
            if entry is None:
                return None
            dn, attributes = entry
            user = self.connect(dn, password)
            try:
                if not user.bind():
                    return None
            finally:
                user.unbind()
        except LDAPException as exc:
            log.warning("ldap error", extra={"error": type(exc).__name__})
            raise ProviderUnavailableError("LDAP request failed") from exc
        return ExternalIdentity(
            username=username,
            display_name=_first(attributes.get(self.settings.ldap_display_name_attribute))[:128],
            roles=self._roles(attributes.get("memberOf")) if self.role_groups else None,
        )

    def _find(self, username: str) -> tuple[str, dict[str, Any]] | None:
        service = self.connect(self.settings.ldap_bind_dn, self._service_password())
        try:
            if not service.bind():
                raise ProviderUnavailableError("LDAP service account bind failed")
            query = self.settings.ldap_user_filter.replace(
                "{username}", escape_filter_chars(username)
            )
            service.search(
                self.settings.ldap_user_base,
                query,
                search_scope=SUBTREE,
                attributes=["memberOf", self.settings.ldap_display_name_attribute],
                size_limit=2,
            )
            entries = [e for e in service.response or [] if e.get("type") == "searchResEntry"]
        finally:
            service.unbind()
        if len(entries) != 1:  # unknown, or ambiguous: never guess which account was meant
            return None
        found = entries[0]
        return str(found["dn"]), dict(found.get("attributes") or {})

    def _roles(self, member_of: Any) -> frozenset[str]:
        groups = {normalise_dn(str(g)) for g in _values(member_of)}
        return frozenset(role for role, dns in self.role_groups.items() if groups & dns)


def _values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list | tuple | set):
        return list(value)
    return [value]


def _first(value: Any) -> str:
    values = _values(value)
    return str(values[0]) if values else ""
