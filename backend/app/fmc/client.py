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
* Hard API limits (300 GET/min per IP, 10 concurrent connections) are respected with
  a client-side token bucket (default 240/min) and a concurrency cap (default 4);
  HTTP 429 is retried with exponential backoff (``Retry-After`` honoured).
* Collections are read with ``offset``/``limit`` paging (max 1000 per page).

TLS: the server certificate is always verified against the internal trust store,
with hostname checking. There is no code path that disables verification.

Everything the FMC returns is treated as untrusted data and validated before use.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.crypto import zeroize
from app.fmc.errors import (
    FmcAuthError,
    FmcProtocolError,
    FmcRateLimitedError,
    FmcTlsError,
    FmcUnavailableError,
    FmcWriteRejectedError,
)
from app.fmc.validation import TOKEN_RE, UUID_RE, host_for_url

log = logging.getLogger(__name__)

AUTH_BASE = "/api/fmc_platform/v1/auth"
MAX_REFRESHES = 3
MAX_RESPONSE_BYTES = 50 * 1024 * 1024
MAX_PAGE_SIZE = 1000
MAX_PAGES = 100_000

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


@dataclass(frozen=True)
class ThrottlePolicy:
    """Client-side protection of the FMC (and of our shared API session budget)."""

    requests_per_minute: int = 240  # FMC hard limit is 300 GET/min per source IP
    burst: int = 10
    concurrency: int = 4  # FMC hard limit is 10 connections per source IP
    max_retries: int = 5  # on HTTP 429
    backoff_base: float = 2.0
    max_backoff: float = 60.0
    sleep: Callable[[float], Awaitable[None]] = field(default=asyncio.sleep, compare=False)


class TokenBucket:
    """Async token bucket: ``rate_per_minute`` tokens per minute, up to ``burst`` stored."""

    def __init__(
        self,
        rate_per_minute: int,
        burst: int,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_per_minute <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        self._rate = rate_per_minute / 60.0
        self._burst = float(burst)
        self._tokens = float(burst)
        self._sleep = sleep
        self._clock = clock
        self._updated = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = self._clock()
                self._tokens = min(self._burst, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await self._sleep((1 - self._tokens) / self._rate)


class _Paging(BaseModel):
    model_config = ConfigDict(extra="ignore")
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=MAX_PAGE_SIZE)
    count: int = Field(ge=0, le=50_000_000)


class _Page(BaseModel):
    model_config = ConfigDict(extra="ignore")
    items: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_PAGE_SIZE)
    paging: _Paging | None = None


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


def _error_description(response: httpx.Response) -> str:
    """The FMC's error text (``error.messages[].description``), bounded; never raises."""
    try:
        data = response.json()
        messages = data.get("error", {}).get("messages", []) if isinstance(data, dict) else []
        text = "; ".join(str(m.get("description", "")) for m in messages if isinstance(m, dict))
    except ValueError:
        text = ""
    return text[:300]


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
        throttle: ThrottlePolicy | None = None,
    ) -> None:
        self._throttle = throttle or ThrottlePolicy()
        self._bucket = TokenBucket(
            self._throttle.requests_per_minute, self._throttle.burst, self._throttle.sleep
        )
        self._concurrency = asyncio.Semaphore(self._throttle.concurrency)
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

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        header = response.headers.get("Retry-After", "")
        if header.isdigit():
            return min(float(header), self._throttle.max_backoff)
        delay: float = self._throttle.backoff_base * float(2**attempt)
        return min(delay, self._throttle.max_backoff)

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        attempt = 0
        while True:
            await self._bucket.acquire()
            async with self._concurrency:
                try:
                    response = await self._client.request(method, path, **kwargs)
                except httpx.TransportError as exc:
                    if _is_tls_failure(exc):
                        raise FmcTlsError("TLS verification of the FMC failed") from exc
                    raise FmcUnavailableError(f"FMC unreachable: {type(exc).__name__}") from exc
            if response.status_code != 429:
                break
            if attempt >= self._throttle.max_retries:
                raise FmcRateLimitedError("FMC rate limit hit (429), retries exhausted")
            delay = self._retry_delay(response, attempt)
            log.warning("FMC returned 429; backing off", extra={"delay_s": delay, "path": path})
            await self._throttle.sleep(delay)
            attempt += 1
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

    async def get_json(
        self,
        path: str,
        params: dict[str, str | int] | None = None,
        *,
        allow_not_found: bool = False,
    ) -> Any:
        """Authenticated GET; one transparent token refresh on 401.

        With ``allow_not_found`` a 404 returns ``None`` (optional sub-resources such as
        BGP on a device without BGP configuration).
        """
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
            if response.status_code == 404 and allow_not_found:
                return None
            if response.status_code != 200:
                raise FmcProtocolError(
                    f"GET {path} returned HTTP {response.status_code}", response.status_code
                )
            try:
                return response.json()
            except ValueError as exc:
                raise FmcProtocolError(f"GET {path} returned invalid JSON") from exc
        raise FmcProtocolError("unreachable")  # pragma: no cover

    async def write_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
    ) -> Any:
        """Authenticated configuration write (POST / PUT / DELETE).

        Only :mod:`app.enforce.executor` calls this, for an approved batch, under the
        cross-worker write lock. A 4xx answer raises :class:`FmcWriteRejectedError` with the
        FMC's own description (never retried — the caller rolls back); 429 is retried by
        ``_send`` (one write at a time per FMC).
        """
        if method not in ("POST", "PUT", "DELETE"):
            raise ValueError("write_json is for POST, PUT and DELETE")
        for attempt in (1, 2):
            if self._tokens is None:
                raise FmcAuthError("no active FMC session")
            headers = {"X-auth-access-token": self._tokens.access, "Accept": "application/json"}
            response = await self._send(method, path, params=params, json=body, headers=headers)
            if response.status_code == 401 and attempt == 1:
                await self._refresh_token()
                continue
            if response.status_code == 401:
                raise FmcAuthError("FMC rejected the access token")
            if 400 <= response.status_code < 500:
                raise FmcWriteRejectedError(
                    f"{method} {path} rejected with HTTP {response.status_code}",
                    response.status_code,
                    _error_description(response),
                )
            if response.status_code not in (200, 201, 202, 204):
                raise FmcProtocolError(f"{method} {path} returned HTTP {response.status_code}")
            if response.status_code == 204 or not response.content:
                return None
            try:
                return response.json()
            except ValueError as exc:
                raise FmcProtocolError(f"{method} {path} returned invalid JSON") from exc
        raise FmcProtocolError("unreachable")  # pragma: no cover

    async def iter_pages(
        self,
        path: str,
        *,
        start_offset: int = 0,
        page_size: int = MAX_PAGE_SIZE,
        params: dict[str, str | int] | None = None,
        optional: bool = False,
    ) -> AsyncIterator[tuple[int, list[dict[str, Any]]]]:
        """Yield ``(offset, items)`` for every page of an FMC collection (``expanded=true``).

        ``start_offset`` resumes a partially collected resource (checkpointing). An empty
        collection (the FMC omits ``items``) yields nothing.
        """
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise ValueError("page_size must be 1..1000")
        offset = start_offset
        for _ in range(MAX_PAGES):
            query: dict[str, str | int] = {
                "offset": offset,
                "limit": page_size,
                "expanded": "true",
                **(params or {}),
            }
            raw = await self.get_json(path, query, allow_not_found=optional)
            if raw is None:
                return
            try:
                page = _Page.model_validate(raw)
            except ValidationError as exc:
                raise FmcProtocolError(f"GET {path}: malformed page") from exc
            if not page.items:
                return
            yield offset, page.items
            offset += len(page.items)
            total = page.paging.count if page.paging is not None else offset
            if offset >= total:
                return
        raise FmcProtocolError(f"GET {path}: paging did not terminate")
