"""FMC paging, 429 backoff and the token bucket (in-process FMC mock, no network)."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import httpx
import pytest
from fmc_mock.app import GLOBAL_DOMAIN_UUID, create_app
from fmc_mock.auth import TokenStore
from fmc_mock.seed import generate

from app.fmc.client import FmcSession, ThrottlePolicy, TokenBucket
from app.fmc.errors import FmcProtocolError, FmcRateLimitedError

PASSWORD = "Mock-Api-Pass-1"
BASE = f"/api/fmc_config/v1/domain/{GLOBAL_DOMAIN_UUID}"
DATA = generate(clusters=1, rules_per_policy=40, seed=3)


def _session(transport: httpx.AsyncBaseTransport, **throttle: Any) -> FmcSession:
    return FmcSession(
        host="fmc-mock",
        port=443,
        username="api_user",
        password_provider=lambda: bytearray(PASSWORD.encode()),
        ssl_context=ssl.create_default_context(),
        timeout=5,
        transport=transport,
        throttle=ThrottlePolicy(**throttle) if throttle else None,
    )


def _mock() -> httpx.ASGITransport:
    store = TokenStore(username="api_user", password=PASSWORD)
    return httpx.ASGITransport(app=create_app(store=store, data=DATA))


async def _collect(path: str, **kwargs: Any) -> list[tuple[int, list[dict[str, Any]]]]:
    async with _session(_mock()) as fmc:
        return [page async for page in fmc.iter_pages(path, **kwargs)]


def test_pages_cover_the_whole_collection() -> None:
    pages = asyncio.run(_collect(f"{BASE}/object/hosts", page_size=7))
    ids = [item["id"] for _, items in pages for item in items]
    assert len(ids) == len(DATA.objects["hosts"])
    assert len(set(ids)) == len(ids)
    assert [offset for offset, _ in pages] == list(range(0, len(ids), 7))
    assert all("value" in item for _, items in pages for item in items)  # expanded


def test_resume_from_offset() -> None:
    pages = asyncio.run(_collect(f"{BASE}/object/hosts", page_size=10, start_offset=20))
    assert pages[0][0] == 20
    assert sum(len(i) for _, i in pages) == len(DATA.objects["hosts"]) - 20


def test_empty_collection_yields_nothing() -> None:
    assert asyncio.run(_collect(f"{BASE}/object/urlgroups")) == []


def test_optional_404_is_empty_but_required_404_fails() -> None:
    path = f"{BASE}/devices/devicerecords/missing/routing/bgp"
    assert asyncio.run(_collect(path, optional=True)) == []
    with pytest.raises(FmcProtocolError):
        asyncio.run(_collect(path))


def test_invalid_page_size() -> None:
    with pytest.raises(ValueError, match="page_size"):
        asyncio.run(_collect(f"{BASE}/object/hosts", page_size=1001))


def test_malformed_page_rejected() -> None:
    good = _mock()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/object/hosts"):
            return httpx.Response(200, json={"items": "nope", "paging": {"count": 1}})
        return await good.handle_async_request(request)

    async def run() -> None:
        async with _session(httpx.MockTransport(handler)) as fmc:
            async for _ in fmc.iter_pages(f"{BASE}/object/hosts"):
                pass

    with pytest.raises(FmcProtocolError, match="malformed page"):
        asyncio.run(run())


def test_empty_collection_as_the_real_fmc_reports_it() -> None:
    # FMC 10.1 answers an empty collection with no items and "limit": 0 (seen on a lab FMC).
    good = _mock()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/object/portobjectgroups"):
            empty = {"links": {}, "paging": {"offset": 0, "limit": 0, "count": 0, "pages": 0}}
            return httpx.Response(200, json=empty)
        return await good.handle_async_request(request)

    async def run() -> list[Any]:
        async with _session(httpx.MockTransport(handler)) as fmc:
            return [page async for page in fmc.iter_pages(f"{BASE}/object/portobjectgroups")]

    assert asyncio.run(run()) == []


def test_retry_after_is_honoured_then_succeeds() -> None:
    good = _mock()
    calls = {"n": 0}
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/object/hosts"):
            calls["n"] += 1
            if calls["n"] <= 2:
                return httpx.Response(429, headers={"Retry-After": "7"})
        return await good.handle_async_request(request)

    async def run() -> int:
        async with _session(httpx.MockTransport(handler), sleep=fake_sleep) as fmc:
            return sum([len(i) async for _, i in fmc.iter_pages(f"{BASE}/object/hosts")])

    assert asyncio.run(run()) == len(DATA.objects["hosts"])
    assert [s for s in slept if s >= 1] == [7.0, 7.0]


def test_backoff_exhaustion() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if "generatetoken" in request.url.path:
            return httpx.Response(
                204,
                headers={
                    "X-auth-access-token": "a" * 36,
                    "X-auth-refresh-token": "b" * 36,
                    "DOMAIN_UUID": GLOBAL_DOMAIN_UUID,
                },
            )
        return httpx.Response(429)

    async def no_sleep(_: float) -> None:
        return None

    async def run() -> None:
        async with _session(httpx.MockTransport(handler), sleep=no_sleep, max_retries=2) as fmc:
            await fmc.get_json(f"{BASE}/object/hosts")

    with pytest.raises(FmcRateLimitedError):
        asyncio.run(run())


def test_token_bucket_enforces_rate() -> None:
    now = [0.0]
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    bucket = TokenBucket(rate_per_minute=60, burst=3, sleep=fake_sleep, clock=lambda: now[0])

    async def run() -> None:
        for _ in range(6):
            await bucket.acquire()

    asyncio.run(run())
    assert slept == pytest.approx([1.0, 1.0, 1.0])  # burst of 3, then 1 per second
    with pytest.raises(ValueError, match="positive"):
        TokenBucket(rate_per_minute=0, burst=1)
