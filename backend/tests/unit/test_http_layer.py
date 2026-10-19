"""Middleware and error handlers on a minimal app (no DB / Redis needed)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import register_error_handlers
from app.core.middleware import SECURITY_HEADERS, SecurityMiddleware


class Body(BaseModel):
    password: str
    count: int


def _app() -> FastAPI:
    app = FastAPI()
    register_error_handlers(app)

    @app.post("/echo")
    def echo(body: Body) -> dict[str, int]:
        return {"count": body.count}

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("database password=hunter2 leaked in message")

    app.add_middleware(SecurityMiddleware, max_body_bytes=1024)
    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app(), raise_server_exceptions=False)


def test_security_headers_and_request_id(client: TestClient) -> None:
    resp = client.post("/echo", json={"password": "x", "count": 1})
    assert resp.status_code == 200
    for name, value in SECURITY_HEADERS.items():
        assert resp.headers[name] == value
    assert len(resp.headers["X-Request-ID"]) == 32


def test_validation_error_does_not_echo_input(client: TestClient) -> None:
    resp = client.post("/echo", json={"password": "SuperSecret-123", "count": "many"})
    assert resp.status_code == 422
    assert "SuperSecret-123" not in resp.text
    assert "many" not in resp.text
    body = resp.json()
    assert body["detail"] == "validation_error"
    assert body["errors"][0]["loc"] == ["body", "count"]


def test_unhandled_error_is_generic(client: TestClient) -> None:
    resp = client.get("/boom")
    assert resp.status_code == 500
    assert resp.json()["detail"] == "internal_error"
    assert "hunter2" not in resp.text
    assert "Traceback" not in resp.text
    assert resp.headers["X-Request-ID"] == resp.json()["request_id"]


def test_http_errors_keep_status(client: TestClient) -> None:
    resp = client.get("/missing")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Not Found"


def test_declared_body_too_large(client: TestClient) -> None:
    resp = client.post("/echo", content=b"x" * 2048, headers={"content-type": "application/json"})
    assert resp.status_code == 413
    assert resp.json() == {"detail": "request_too_large"}


def test_streamed_body_too_large(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(4):
            yield b"x" * 512

    resp = client.post("/echo", content=chunks(), headers={"content-type": "application/json"})
    assert resp.status_code == 413
