"""Network faults on configuration writes (test-only, switched on through ``/mock/faults``).

* ``lost_answer_on: <text>`` — a write whose body or path contains the text is applied, but
  the answer is lost (HTTP 504 from the gateway): the client cannot know whether it landed.
* ``outage_on: <text>`` — the same, and from then on every configuration write fails with
  HTTP 503 (the FMC went away mid-batch) until the faults are cleared.
"""

from __future__ import annotations

from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fmc_mock.limits import WRITE_METHODS, _respond

_EXEMPT = ("/api/fmc_platform/v1/auth/", "/mock/")


class NetworkFaultsMiddleware:
    def __init__(self, app: ASGIApp, state: Any) -> None:
        self.app = app
        self.state = state  # fmc_mock.writes.WriteState

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        faults = self.state.faults
        path: str = scope.get("path", "")
        if (
            scope["type"] != "http"
            or scope["method"] not in WRITE_METHODS
            or path.startswith(_EXEMPT)
            or not any(k in faults for k in ("lost_answer_on", "outage_on", "outage"))
        ):
            await self.app(scope, receive, send)
            return
        if faults.get("outage"):
            await _respond(send, 503, b'{"error":"service unavailable"}')
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = b"".join(chunks)
        text = body.decode("utf-8", "replace") + path
        needle = next(
            (
                (key, str(faults[key]))
                for key in ("outage_on", "lost_answer_on")
                if isinstance(faults.get(key), str) and faults[key] and faults[key] in text
            ),
            None,
        )
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        if needle is None:
            await self.app(scope, replay, send)
            return
        status = 0

        async def swallow(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])

        await self.app(scope, replay, swallow)
        if 200 <= status < 300:
            if needle[0] == "outage_on":
                faults["outage"] = True
            await _respond(send, 504, b'{"error":"gateway timeout"}')
            return
        await _respond(send, status or 500, b'{"error":"write failed"}')
