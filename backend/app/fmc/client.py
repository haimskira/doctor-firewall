"""Read-only FMC REST client core (FMC 10.1 conventions).

Procedures implemented here (Cisco FMC REST API Quick Start Guide 10.1):

* Token from ``POST /api/fmc_platform/v1/auth/generatetoken`` with HTTP Basic and an
  empty body; the response headers carry ``X-auth-access-token``,
  ``X-auth-refresh-token`` and ``DOMAIN_UUID``.
* Every call sends ``X-auth-access-token``. A token lives 30 minutes and can be
  refreshed up to 3 times via ``/auth/refreshtoken``; after that a new token is
  generated. One token is reused for the whole session (no token-per-call, which
  would exhaust the FMC's shared API/UI session limit).
* The token is revoked (``/auth/revokeaccess``) when the session ends.

TLS: the server certificate is always verified against the internal trust store,
with hostname checking. There is no code path that disables verification.

Everything the FMC returns is treated as untrusted data and validated before use.
"""

from __future__ import annotations

import base64
import logging
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx

from app.core.crypto import zeroize
from app.fmc.errors import (
    FmcAuthError,
    FmcProtocolError,
    FmcRateLimitedError,
    FmcTlsError,
    FmcUnavailableError,
)
from app.fmc.validation import TOKEN_RE, UUID_RE, host_for_url

log = logging.getLogger(__name__)

AUTH_BASE = "/api/fmc_platform/v1/auth"
MAX_REFRESHES = 3
MAX_RESPONSE_BYTES = 50 * 1024 * 1024

# Returns the API password freshly decrypted; the client zeroizes it after use.
PasswordProvider = Callable[[], bytearray]


def build_ssl_context(ca_bundle: Path) -> ssl.SSLContext:
    if not ca_bundle.is_file():
        raise FmcTlsError(f"FMC trust store not found at {ca_bundle}")
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_bundle))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not ctx.check_hostname or ctx.verify_mode != ssl.CERT_REQUIRED:  # pragma: no cover
        raise FmcTlsError("refusing an SSL context without full verification")
    return ctx


@dataclass
class _Tokens:
    access: str
    refresh: str
    domain_uuid: str
    refreshes: int = 0


def _is_tls_failure(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


class FmcSession:
    """An authenticated session against one FMC. Use as ``async with``."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password_provider: PasswordProvider,
        ssl_context: ssl.SSLContext,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._username = username
        self._password_provider = password_provider
        self._client = httpx.AsyncClient(
            base_url=f"https://{host_for_url(host)}:{port}",
            verify=ssl_context,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,  # never pick up proxy settings from the environment
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            transport=transport,
        )
        self._tokens: _Tokens | None = None

    async def __aenter__(self) -> Self:
        try:
            await self._generate_token()
        except BaseException:
            await self._client.aclose()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await self._revoke()
        finally:
            await self._client.aclose()

    @property
    def domain_uuid(self) -> str:
        if self._tokens is None:
            raise FmcAuthError("no active FMC session")
        return self._tokens.domain_uuid

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.TransportError as exc:
            if _is_tls_failure(exc):
                raise FmcTlsError("TLS verification of the FMC failed") from exc
            raise FmcUnavailableError(f"FMC unreachable: {type(exc).__name__}") from exc
        if response.status_code == 429:
            raise FmcRateLimitedError("FMC rate limit hit (429)")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise FmcProtocolError("FMC response exceeds size limit")
        return response

    def _basic_auth_header(self) -> str:
        password = self._password_provider()
        raw = bytearray(self._username.encode()) + b":" + password
        try:
            return "Basic " + base64.b64encode(raw).decode("ascii")
        finally:
            zeroize(password)
            zeroize(raw)

    async def _generate_token(self) -> None:
        response = await self._send(
            "POST",
            f"{AUTH_BASE}/generatetoken",
            headers={"Authorization": self._basic_auth_header()},
        )
        if response.status_code == 401:
            raise FmcAuthError("FMC rejected the API credentials")
        if response.status_code not in (200, 204):
            raise FmcProtocolError(f"generatetoken returned HTTP {response.status_code}")
        self._tokens = self._parse_token_headers(response)

    @staticmethod
    def _parse_token_headers(response: httpx.Response) -> _Tokens:
        access = response.headers.get("X-auth-access-token", "")
        refresh = response.headers.get("X-auth-refresh-token", "")
        domain = response.headers.get("DOMAIN_UUID", "")
        if not (TOKEN_RE.fullmatch(access) and TOKEN_RE.fullmatch(refresh)):
            raise FmcProtocolError("FMC token headers missing or malformed")
        if not UUID_RE.fullmatch(domain):
            raise FmcProtocolError("FMC DOMAIN_UUID header missing or malformed")
        return _Tokens(access=access, refresh=refresh, domain_uuid=domain.lower())

    async def _refresh_token(self) -> None:
        if self._tokens is None or self._tokens.refreshes >= MAX_REFRESHES:
            await self._generate_token()
            return
        response = await self._send(
            "POST",
            f"{AUTH_BASE}/refreshtoken",
            headers={
                "X-auth-access-token": self._tokens.access,
                "X-auth-refresh-token": self._tokens.refresh,
            },
        )
        if response.status_code not in (200, 204):
            await self._generate_token()
            return
        refreshes = self._tokens.refreshes + 1
        self._tokens = self._parse_token_headers(response)
        self._tokens.refreshes = refreshes

    async def _revoke(self) -> None:
        if self._tokens is None:
            return
        tokens, self._tokens = self._tokens, None
        try:
            await self._send(
                "POST",
                f"{AUTH_BASE}/revokeaccess",
                headers={"X-auth-access-token": tokens.access},
            )
        except (FmcUnavailableError, FmcRateLimitedError, FmcTlsError, FmcProtocolError):
            # The token expires by itself within 30 minutes; do not mask the real outcome.
            log.warning("FMC token revoke failed; token will expire on its own")

    async def get_json(self, path: str, params: dict[str, str | int] | None = None) -> Any:
        """Authenticated GET; one transparent token refresh on 401."""
        for attempt in (1, 2):
            if self._tokens is None:
                raise FmcAuthError("no active FMC session")
            response = await self._send(
                "GET",
                path,
                params=params,
                headers={"X-auth-access-token": self._tokens.access, "Accept": "application/json"},
            )
            if response.status_code == 401 and attempt == 1:
                await self._refresh_token()
                continue
            if response.status_code == 401:
                raise FmcAuthError("FMC rejected the access token")
            if response.status_code != 200:
                raise FmcProtocolError(f"GET {path} returned HTTP {response.status_code}")
            try:
                return response.json()
            except ValueError as exc:
                raise FmcProtocolError(f"GET {path} returned invalid JSON") from exc
        raise FmcProtocolError("unreachable")  # pragma: no cover
