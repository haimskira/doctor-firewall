"""Behaviour of the FMC mock itself, so tests built on it are trustworthy."""

from __future__ import annotations

import asyncio
import base64

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.types import Receive, Scope, Send

from fmc_mock.app import GLOBAL_DOMAIN_UUID, create_app
from fmc_mock.auth import TokenStore
from fmc_mock.limits import FmcLimitsMiddleware

AUTH = "/api/fmc_platform/v1/auth"


def _basic(user: str, password: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


@pytest.fixture
def store() -> TokenStore:
    return TokenStore(username="api_user", password="pw")


def _client(store: TokenStore, get_per_minute: int = 300) -> TestClient:
    return TestClient(create_app(store=store, get_per_minute=get_per_minute))


def test_generate_refresh_revoke(store: TokenStore) -> None:
    client = _client(store)
    resp = client.post(f"{AUTH}/generatetoken", headers=_basic("api_user", "pw"))
    assert resp.status_code == 204
    assert resp.headers["DOMAIN_UUID"] == GLOBAL_DOMAIN_UUID
    access, refresh = resp.headers["X-auth-access-token"], resp.headers["X-auth-refresh-token"]
    for _ in range(3):
        resp = client.post(
            f"{AUTH}/refreshtoken",
            headers={"X-auth-access-token": access, "X-auth-refresh-token": refresh},
        )
        assert resp.status_code == 204
        access, refresh = resp.headers["X-auth-access-token"], resp.headers["X-auth-refresh-token"]
    # The 4th refresh is refused, as on a real FMC.
    resp = client.post(
        f"{AUTH}/refreshtoken",
        headers={"X-auth-access-token": access, "X-auth-refresh-token": refresh},
    )
    assert resp.status_code == 401
    assert (
        client.post(f"{AUTH}/revokeaccess", headers={"X-auth-access-token": access}).status_code
        == 204
    )
    assert (
        client.post(f"{AUTH}/revokeaccess", headers={"X-auth-access-token": access}).status_code
        == 401
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer x"},
        {"Authorization": "Basic !!!"},
        {"Authorization": "Basic " + base64.b64encode(b"nocolon").decode()},
    ],
)
def test_bad_basic_auth(store: TokenStore, headers: dict[str, str]) -> None:
    assert _client(store).post(f"{AUTH}/generatetoken", headers=headers).status_code == 401


def test_wrong_password(store: TokenStore) -> None:
    resp = _client(store).post(f"{AUTH}/generatetoken", headers=_basic("api_user", "nope"))
    assert resp.status_code == 401


def test_requires_valid_token(store: TokenStore) -> None:
    client = _client(store)
    assert client.get("/api/fmc_platform/v1/info/serverversion").status_code == 401
    token = client.post(f"{AUTH}/generatetoken", headers=_basic("api_user", "pw")).headers[
        "X-auth-access-token"
    ]
    ok = client.get(
        "/api/fmc_platform/v1/info/serverversion", headers={"X-auth-access-token": token}
    )
    assert ok.status_code == 200
    store.expire_all()
    expired = client.get(
        "/api/fmc_platform/v1/info/serverversion", headers={"X-auth-access-token": token}
    )
    assert expired.status_code == 401


def test_get_rate_limit(store: TokenStore) -> None:
    client = _client(store, get_per_minute=3)
    codes = [client.get("/api/fmc_platform/v1/info/serverversion").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3:] == [429, 429]


def test_payload_limit(store: TokenStore) -> None:
    resp = _client(store).post("/api/fmc_config/v1/anything", content=b"x" * 2_048_001)
    assert resp.status_code == 422


def _gated_app(gate: asyncio.Event) -> FmcLimitsMiddleware:
    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    return FmcLimitsMiddleware(inner)


def test_only_one_write_at_a_time() -> None:
    async def run() -> list[int]:
        gate = asyncio.Event()
        transport = httpx.ASGITransport(app=_gated_app(gate))
        async with httpx.AsyncClient(transport=transport, base_url="http://fmc") as client:
            first = asyncio.create_task(client.put("/api/fmc_config/v1/x", content=b"{}"))
            await asyncio.sleep(0.05)
            second = await client.post("/api/fmc_config/v1/y", content=b"{}")
            gate.set()
            return [(await first).status_code, second.status_code]

    assert asyncio.run(run()) == [200, 429]


def test_concurrent_connection_cap() -> None:
    async def run() -> list[int]:
        gate = asyncio.Event()
        transport = httpx.ASGITransport(app=_gated_app(gate))
        async with httpx.AsyncClient(transport=transport, base_url="http://fmc") as client:
            held = [asyncio.create_task(client.get(f"/r/{i}")) for i in range(10)]
            await asyncio.sleep(0.05)
            extra = await client.get("/r/extra")
            gate.set()
            return [extra.status_code, *[(await t).status_code for t in held]]

    codes = asyncio.run(run())
    assert codes[0] == 429
    assert codes[1:] == [200] * 10
