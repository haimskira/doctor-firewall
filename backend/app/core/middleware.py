"""Pure-ASGI middleware: request id, body-size cap, security headers, fail-closed 500s.

nginx sets the same headers for the static UI; the API sets its own so it is safe
even when reached without nginx (e.g. tests).

This middleware is the outermost layer that the application controls, so it also
turns any unhandled exception into a generic 500 (with headers and request id)
before Starlette's default error middleware could render anything else.
"""

from __future__ import annotations

import json
import logging
import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)

SECURITY_HEADERS: dict[str, str] = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def _json_response_messages(
    status: int, payload: dict[str, str], request_id: str
) -> tuple[Message, Message]:
    body = json.dumps(payload).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"x-request-id", request_id.encode()),
        *[(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()],
    ]
    return (
        {"type": "http.response.start", "status": status, "headers": headers},
        {"type": "http.response.body", "body": body},
    )


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        declared = _content_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            for message in _json_response_messages(
                413, {"detail": "request_too_large"}, request_id
            ):
                await send(message)
            return

        received = 0
        too_large = False
        started = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    # Stop feeding the app; whatever it answers is replaced by a 413.
                    too_large = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if too_large:
                if message["type"] == "http.response.start" and not started:
                    started = True
                    start, body = _json_response_messages(
                        413, {"detail": "request_too_large"}, request_id
                    )
                    await send(start)
                    await send(body)
                return
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                headers["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            log.exception(
                "unhandled error", extra={"request_id": request_id, "path": scope.get("path", "")}
            )
            if started:
                raise
            for message in _json_response_messages(
                500, {"detail": "internal_error", "request_id": request_id}, request_id
            ):
                await send(message)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None
