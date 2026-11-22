"""FMC integration log: every request and every failed operation, with the failing step."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.collector import runner
from app.fmc.client import ThrottlePolicy
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_collection import _collect, _connection, _snapshot
from tests.integration.test_phase5_writes import _fresh_mock, mock

__all__ = ["_fresh_mock"]


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("log-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "log-admin")}


def _events(client: TestClient, **params: str | int) -> list[dict[str, object]]:
    query: dict[str, str | int] = {"limit": 500, **params}
    resp = client.get("/api/fmc/events", params=query)
    assert resp.status_code == 200, resp.text
    rows: list[dict[str, object]] = resp.json()["rows"]
    return rows


def test_connection_test_is_logged_request_by_request(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn = _connection(client, admin)
    assert client.post(f"/api/fmc/connections/{conn}/test", headers=admin).json()["ok"] is True
    (op,) = _events(client, operation="test", kind="finished", connection_id=conn)[:1]
    assert op["outcome"] == "ok"
    steps = _events(client, op=str(op["op_id"]))
    kinds = [e["kind"] for e in reversed(steps)]
    assert kinds[0] == "started"
    assert kinds[-1] == "finished"
    paths = [str(e["path"]) for e in steps if e["kind"] == "request"]
    assert any(p.endswith("/auth/generatetoken") for p in paths)
    assert any("/info/serverversion" in p for p in paths)
    assert all(e["connection_name"] == "FMC-HA" for e in steps)
    assert all(e["response"] == "" for e in steps)  # bodies only for failed requests


def test_a_failed_collection_names_the_step_status_and_fmc_answer(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn = _connection(client, admin)
    sid = _collect(client, admin, conn)
    mock("POST", "/mock/faults", {"fail_read_on": "/accessrules"})
    result = jobs.collect_snapshot(sid)
    assert result["ok"] is False
    assert _snapshot(sid).status == "failed"

    events = _events(client, snapshot_id=sid)
    failed = [e for e in events if e["kind"] == "failed"]
    assert failed, events[:5]
    assert failed[0]["error_code"] == "unexpected_response"
    assert "accessrules" in str(failed[0]["step"])
    assert "HTTP 500" in str(failed[0]["detail"])
    bad = [e for e in events if e["kind"] == "request" and e["status"] == 500]
    assert bad
    assert "/accessrules" in str(bad[0]["path"])
    assert "offset=" in str(bad[0]["path"])
    assert "Unexpected internal error" in str(bad[0]["response"])
    assert "accessrules" in str(bad[0]["step"])
    finished = [e for e in events if e["kind"] == "finished"]
    assert finished[0]["outcome"] == "error"
    assert "requests" in str(finished[0]["detail"])

    only_errors = _events(client, snapshot_id=sid, outcome="error")
    assert {e["outcome"] for e in only_errors} == {"error"}
    found = _events(client, q="accessrules", snapshot_id=sid)
    assert found
    assert all(
        "accessrules" in f"{e['path']}{e['step']}{e['detail']}{e['error_code']}" for e in found
    )

    export = client.get("/api/fmc/events/export", params={"snapshot_id": sid})
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    lines = export.text.lstrip("﻿").splitlines()
    assert lines[0].startswith("at,op_id,operation")
    assert len(lines) > 3


def test_no_secret_reaches_the_log(client: TestClient, admin: dict[str, str]) -> None:
    conn = _connection(client, admin)
    sid = _collect(client, admin, conn)
    assert jobs.collect_snapshot(sid)["ok"] is True
    export = client.get("/api/fmc/events/export", params={"snapshot_id": sid}).text
    for marker in ("X-auth-access-token", "Authorization", "Basic ", "password"):
        assert marker not in export


def test_the_log_needs_audit_permission(client: TestClient, admin: dict[str, str]) -> None:
    make_user("log-viewer", ["viewer"])
    login(client, "log-viewer")
    assert client.get("/api/fmc/events").status_code == 403
    assert client.get("/api/fmc/events/export").status_code == 403
    login(client, "log-admin")
    for params in ({"op": "nothex"}, {"operation": "nope"}, {"limit": 0}, {"q": "x" * 200}):
        assert client.get("/api/fmc/events", params=params).status_code == 422, params
