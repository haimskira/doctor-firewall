"""FMC 10.1 hard API limits, emulated so the real client is tested against them.

* GET: at most 300 per minute per client IP            -> 429
* Writes (POST/PUT/DELETE): one at a time per server   -> 429
* Concurrent connections: at most 10 per client IP     -> 429
* Request payload: at most 2,048,000 bytes             -> 422
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from starlette.types import ASGIApp, Receive, Scope, Send

GET_PER_MINUTE = 300
MAX_CONCURRENT_PER_IP = 10
MAX_PAYLOAD_BYTES = 2_048_000
WRITE_METHODS = frozenset({"POST", "PUT", "DELETE"})
# Auth endpoints are POSTs but are not configuration writes.
_AUTH_PREFIX = "/api/fmc_platform/v1/auth/"
_PAYLOAD_TOO_LARGE = b'{"error":{"messages":[{"description":"payload too large"}]}}'


async def _respond(send: Send, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class FmcLimitsMiddleware:
    def __init__(self, app: ASGIApp, get_per_minute: int = GET_PER_MINUTE) -> None:
        self.app = app
        self.get_per_minute = get_per_minute
        self._gets: dict[str, deque[float]] = defaultdict(deque)
        self._active: dict[str, int] = defaultdict(int)
        self._write_lock = asyncio.Lock()

    def reset(self) -> None:
        self._gets.clear()
        self._active.clear()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        ip = client[0] if client else "unknown"
        method: str = scope["method"]
        path: str = scope["path"]

        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > MAX_PAYLOAD_BYTES:
                await _respond(send, 422, _PAYLOAD_TOO_LARGE)
                return

        if self._active[ip] >= MAX_CONCURRENT_PER_IP:
            await _respond(send, 429, b'{"error":"too many connections"}')
            return

        if method == "GET":
            now = time.monotonic()
            window = self._gets[ip]
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= self.get_per_minute:
                await _respond(send, 429, b'{"error":"rate limit exceeded"}')
                return
            window.append(now)

        is_write = method in WRITE_METHODS and not path.startswith(_AUTH_PREFIX)
        if is_write and self._write_lock.locked():
            await _respond(send, 429, b'{"error":"another write is in progress"}')
            return

        self._active[ip] += 1
        try:
            if is_write:
                async with self._write_lock:
                    await self.app(scope, receive, send)
            else:
                await self.app(scope, receive, send)
        finally:
            self._active[ip] -= 1
