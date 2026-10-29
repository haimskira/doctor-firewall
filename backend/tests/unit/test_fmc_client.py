"""FMC client against the in-process FMC mock (no network; TLS is covered by integration tests)."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from fmc_mock.app import GLOBAL_DOMAIN_UUID, SERVER_VERSION, create_app
from fmc_mock.auth import TokenStore

from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import (
    FmcAuthError,
    FmcProtocolError,
    FmcRateLimitedError,
    FmcTlsError,
    FmcUnavailableError,
)
from app.fmc.probe import SERVER_VERSION_PATH, probe
from app.tools.certs import main as certs_main

PASSWORD = "Mock-Api-Pass-1"


@pytest.fixture
def store() -> TokenStore:
    return TokenStore(username="api_user", password=PASSWORD)


def _transport(store: TokenStore, get_per_minute: int = 300) -> httpx.ASGITransport:
    return httpx.ASGITransport(app=create_app(store=store, get_per_minute=get_per_minute))


def _ssl() -> ssl.SSLContext:
    return ssl.create_default_context()


def _session(
    store: TokenStore,
    password: str = PASSWORD,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FmcSession:
    return FmcSession(
        host="fmc-mock",
        port=443,
        username="api_user",
        password_provider=lambda: bytearray(password.encode()),
        ssl_context=_ssl(),
        timeout=5,
        transport=transport or _transport(store),
    )


def test_probe_success_and_token_revoked(store: TokenStore) -> None:
    result = asyncio.run(
        probe(
            host="fmc-mock",
            port=443,
            username="api_user",
            password_provider=lambda: bytearray(PASSWORD.encode()),
            ssl_context=_ssl(),
            timeout=5,
            transport=_transport(store),
        )
    )
    assert result.server_version == SERVER_VERSION
    assert result.domain_uuid == GLOBAL_DOMAIN_UUID
    assert store.tokens == {}  # revoked on exit


def test_password_buffer_is_zeroized(store: TokenStore) -> None:
    buffers: list[bytearray] = []

    def provider() -> bytearray:
        buf = bytearray(PASSWORD.encode())
        buffers.append(buf)
        return buf

    async def run() -> None:
        async with FmcSession(
            host="fmc-mock",
            port=443,
            username="api_user",
            password_provider=provider,
            ssl_context=_ssl(),
            timeout=5,
            transport=_transport(store),
        ):
            pass

    asyncio.run(run())
    assert buffers
    assert all(b == bytearray(len(b)) for b in buffers)


def test_bad_credentials(store: TokenStore) -> None:
    async def run() -> None:
        async with _session(store, password="wrong"):
            pass

    with pytest.raises(FmcAuthError):
        asyncio.run(run())


def test_refresh_then_regenerate_after_three_refreshes(store: TokenStore) -> None:
    async def run() -> None:
        async with _session(store) as session:
            for _ in range(5):
                store.expire_all()
                data = await session.get_json(SERVER_VERSION_PATH)
                assert data["items"][0]["serverVersion"] == SERVER_VERSION

    asyncio.run(run())


def test_rate_limit_backs_off_then_surfaces(store: TokenStore) -> None:
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    async def run() -> None:
        async with FmcSession(
            host="fmc-mock",
            port=443,
            username="api_user",
            password_provider=lambda: bytearray(PASSWORD.encode()),
            ssl_context=_ssl(),
            timeout=5,
            transport=_transport(store, get_per_minute=2),
            throttle=ThrottlePolicy(max_retries=3, sleep=fake_sleep),
        ) as session:
            for _ in range(3):
                await session.get_json(SERVER_VERSION_PATH)

    with pytest.raises(FmcRateLimitedError):
        asyncio.run(run())
    backoffs = [s for s in slept if s >= 1]
    assert backoffs == [2.0, 4.0, 8.0]  # exponential, then give up


def _handler_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_malformed_token_headers_rejected(store: TokenStore) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, headers={"X-auth-access-token": "x;y", "DOMAIN_UUID": "nope"})

    async def run() -> None:
        async with _session(store, transport=_handler_transport(handler)):
            pass

    with pytest.raises(FmcProtocolError):
        asyncio.run(run())


def test_bad_domain_uuid_rejected(store: TokenStore) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            204,
            headers={
                "X-auth-access-token": "a" * 36,
                "X-auth-refresh-token": "b" * 36,
                "DOMAIN_UUID": "../../etc",
            },
        )

    async def run() -> None:
        async with _session(store, transport=_handler_transport(handler)):
            pass

    with pytest.raises(FmcProtocolError):
        asyncio.run(run())


def test_invalid_serverversion_payload(store: TokenStore) -> None:
    good = _transport(store)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SERVER_VERSION_PATH:
            return httpx.Response(200, json={"items": [{"serverVersion": "x" * 1000}]})
        return await good.handle_async_request(request)

    with pytest.raises(FmcProtocolError):
        asyncio.run(
            probe(
                host="fmc-mock",
                port=443,
                username="api_user",
                password_provider=lambda: bytearray(PASSWORD.encode()),
                ssl_context=_ssl(),
                timeout=5,
                transport=httpx.MockTransport(handler),
            )
        )


def test_non_json_and_http_errors(store: TokenStore) -> None:
    good = _transport(store)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/bad-json":
            return httpx.Response(200, content=b"<html>")
        if request.url.path == "/boom":
            return httpx.Response(500)
        return await good.handle_async_request(request)

    async def run(path: str) -> None:
        async with _session(store, transport=httpx.MockTransport(handler)) as session:
            await session.get_json(path)

    for path in ("/bad-json", "/boom"):
        with pytest.raises(FmcProtocolError):
            asyncio.run(run(path))


def test_connection_errors_map_to_unavailable_and_tls(store: TokenStore) -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    def tls(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("tls") from ssl.SSLCertVerificationError("bad cert")

    async def run(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        async with _session(store, transport=_handler_transport(handler)):
            pass

    with pytest.raises(FmcUnavailableError):
        asyncio.run(run(refused))
    with pytest.raises(FmcTlsError):
        asyncio.run(run(tls))


def test_connection_refused_is_retried_then_surfaces(store: TokenStore) -> None:
    """A brief network loss: the request never left, so it is retried (writes included)."""
    good = _transport(store)
    slept: list[float] = []
    failures = {"left": 0}
    sent: list[str] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    async def handler(request: httpx.Request) -> httpx.Response:
        if failures["left"] > 0:
            failures["left"] -= 1
            raise httpx.ConnectError("no route to host")
        sent.append(request.method)
        return await good.handle_async_request(request)

    def session() -> FmcSession:
        return FmcSession(
            host="fmc-mock",
            port=443,
            username="api_user",
            password_provider=lambda: bytearray(PASSWORD.encode()),
            ssl_context=_ssl(),
            timeout=5,
            transport=httpx.MockTransport(handler),
            throttle=ThrottlePolicy(connect_retries=3, sleep=fake_sleep),
        )

    async def run(fail: int) -> None:
        async with session() as fmc:
            failures["left"] = fail
            await fmc.get_json(SERVER_VERSION_PATH)

    asyncio.run(run(2))
    assert [s for s in slept if s >= 1] == [2.0, 4.0]
    slept.clear()
    with pytest.raises(FmcUnavailableError):
        asyncio.run(run(4))
    assert [s for s in slept if s >= 1] == [2.0, 4.0, 8.0]


def test_read_failures_are_never_retried(store: TokenStore) -> None:
    """After the request may have reached the FMC a retry could repeat a write."""
    good = _transport(store)
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/write":
            calls["n"] += 1
            raise httpx.ReadTimeout("no answer")
        return await good.handle_async_request(request)

    async def run() -> None:
        async with FmcSession(
            host="fmc-mock",
            port=443,
            username="api_user",
            password_provider=lambda: bytearray(PASSWORD.encode()),
            ssl_context=_ssl(),
            timeout=5,
            transport=httpx.MockTransport(handler),
            throttle=ThrottlePolicy(connect_retries=3),
        ) as fmc:
            await fmc.write_json("POST", "/write", {"name": "x"})

    with pytest.raises(FmcUnavailableError):
        asyncio.run(run())
    assert calls["n"] == 1


def test_dropped_connection_retries_reads_but_never_writes(store: TokenStore) -> None:
    """Found on the lab FMC: a kept-alive connection dropped while a deploy was polled failed
    the whole batch. A read is repeated; a write that may have landed is not."""
    good = _transport(store)
    drops = {"GET": 0, "POST": 0}
    calls = {"GET": 0, "POST": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/read", "/write"):
            calls[request.method] += 1
            if drops[request.method] > 0:
                drops[request.method] -= 1
                raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
            return httpx.Response(200, json={"ok": True})
        return await good.handle_async_request(request)

    async def noop(_: float) -> None:
        return None

    async def run() -> None:
        async with FmcSession(
            host="fmc-mock",
            port=443,
            username="api_user",
            password_provider=lambda: bytearray(PASSWORD.encode()),
            ssl_context=_ssl(),
            timeout=5,
            transport=httpx.MockTransport(handler),
            throttle=ThrottlePolicy(connect_retries=3, sleep=noop),
        ) as fmc:
            drops["GET"] = 2
            assert await fmc.get_json("/read") == {"ok": True}
            drops["POST"] = 1
            with pytest.raises(FmcUnavailableError):
                await fmc.write_json("POST", "/write", {"name": "x"})

    asyncio.run(run())
    assert calls == {"GET": 3, "POST": 1}


def test_build_ssl_context(tmp_path: Path) -> None:
    with pytest.raises(FmcTlsError):
        build_ssl_context(tmp_path / "missing.pem")
    certs_main(["--out", str(tmp_path), "--leaf", "fmc:fmc.local"])
    ctx = build_ssl_context(tmp_path / "ca.pem")
    assert ctx.check_hostname
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
