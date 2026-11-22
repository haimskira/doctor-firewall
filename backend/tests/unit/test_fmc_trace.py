"""FMC integration log scope: events, failures, scrubbing and batched writes."""

from __future__ import annotations

import time
from typing import Any

import pytest

from app.fmc import trace
from app.fmc.errors import FmcProtocolError


class _Recorder:
    """A stand-in for a DB session factory that keeps the inserted rows."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.statements = 0

    def __call__(self) -> _Recorder:
        return self

    def __enter__(self) -> _Recorder:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def begin(self) -> _Recorder:
        return self

    def execute(self, _statement: object, rows: list[dict[str, Any]] | None = None) -> None:
        self.statements += 1
        if rows:
            self.rows.extend(rows)


def test_nothing_is_recorded_outside_an_operation() -> None:
    assert trace.current() is None
    trace.record_request("GET", "/x", None, time.monotonic(), status=500, body="boom")
    trace.set_step("ignored")
    trace.fail("x", "y")  # no scope: silently ignored


def test_an_operation_records_requests_steps_and_its_outcome() -> None:
    db = _Recorder()
    with trace.tracing("collect", db, snapshot_id=7) as t:  # type: ignore[arg-type]
        trace.bind(connection_id=3, connection_name="FMC-A")
        trace.set_step("access policy P1: accessrules")
        trace.record_request(
            "GET", "/api/a", {"offset": 0, "limit": 1000}, time.monotonic(), status=200
        )
        trace.record_request(
            "GET",
            "/api/b",
            None,
            time.monotonic(),
            status=500,
            body='{"error": "x", "password": "hunter2", "token": "Bearer abc.def"}',
        )
    kinds = [r["kind"] for r in db.rows]
    assert kinds == ["started", "request", "request", "finished"]
    assert {r["op_id"] for r in db.rows} == {t.op_id}
    ok, bad = db.rows[1], db.rows[2]
    assert ok["path"] == "/api/a?offset=0&limit=1000"
    assert ok["outcome"] == "ok"
    assert ok["response"] == ""
    assert bad["outcome"] == "error"
    assert bad["status"] == 500
    assert bad["step"] == "access policy P1: accessrules"
    assert bad["connection_name"] == "FMC-A"
    assert "hunter2" not in bad["response"]
    assert db.rows[-1]["outcome"] == "ok"  # a failed request alone does not fail the operation
    assert db.rows[-1]["detail"] == "2 requests, 1 failed"
    assert trace.current() is None


def test_an_exception_is_recorded_and_raised() -> None:
    db = _Recorder()

    def operation() -> None:
        with trace.tracing("test", db):  # type: ignore[arg-type]
            trace.set_step("token")
            raise FmcProtocolError("generatetoken returned HTTP 403")

    with pytest.raises(FmcProtocolError):
        operation()
    failed = [r for r in db.rows if r["kind"] == "failed"]
    assert failed[0]["error_code"] == "unexpected_response"
    assert "HTTP 403" in failed[0]["detail"]
    assert failed[0]["step"] == "token"
    assert db.rows[-1]["kind"] == "finished"
    assert db.rows[-1]["outcome"] == "error"


def test_a_reported_failure_marks_the_operation_even_after_a_flush(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trace, "FLUSH_EVERY", 2)
    db = _Recorder()
    with trace.tracing("batch", db, batch_id=4):  # type: ignore[arg-type]
        trace.fail("deploy_failed", "the deploy failed on FTD-1")
        for _ in range(5):  # several flushes after the failure
            trace.record_request("GET", "/api/c", None, time.monotonic(), status=200)
    assert db.rows[-1]["kind"] == "finished"
    assert db.rows[-1]["outcome"] == "error"
    assert sum(1 for r in db.rows if r["kind"] == "request") == 5


def test_transport_errors_and_bad_answers_are_kept() -> None:
    db = _Recorder()
    with trace.tracing("collect", db):  # type: ignore[arg-type]
        trace.record_request(
            "GET", "/api/d", None, time.monotonic(), error=TimeoutError("read timed out")
        )
        trace.note_bad_response(
            "/api/e", "<html>proxy login</html>", "invalid JSON in a 200 answer"
        )
    timeout, html = db.rows[1], db.rows[2]
    assert timeout["error_code"] == "TimeoutError"
    assert timeout["status"] is None
    assert timeout["outcome"] == "error"
    assert html["response"] == "<html>proxy login</html>"
    assert html["error_code"] == "unexpected_response"


def test_a_log_write_failure_never_breaks_the_operation() -> None:
    class Broken(_Recorder):
        def execute(self, _statement: object, rows: list[dict[str, Any]] | None = None) -> None:
            raise RuntimeError("database down")

    with trace.tracing("watch", Broken()):  # type: ignore[arg-type]
        trace.record_request("GET", "/api/f", None, time.monotonic(), status=200)
