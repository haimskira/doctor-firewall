"""FMC integration log: every request to the FMC and every failed FMC operation, kept in the DB.

An operation (connection test, collection, batch, revert, rollback, deploy watch) opens a
:func:`tracing` scope; :class:`app.fmc.client.FmcSession` records each HTTP exchange into the
scope's buffer (method, path with query, status, duration, the FMC's error body when it failed),
the collector names the step it is in (``policy ACP-1: accessrules``), and the scope records the
operation's start, its outcome and the error that ended it. The buffer is written in bulk.

Nothing secret is ever recorded: request headers (credentials, tokens) and request bodies are
not stored at all, response bodies only for failed requests, truncated and scrubbed like logs.
Events older than ``RETENTION_DAYS`` are pruned when a scope closes.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import delete, insert
from sqlalchemy.orm import Session

from app.core.logging import scrub_text
from app.models.fmc import FmcEvent

log = logging.getLogger(__name__)

OPERATIONS = ("test", "collect", "batch", "revert", "rollback", "watch")
RETENTION_DAYS = 30
FLUSH_EVERY = 200
MAX_DETAIL = 2000
MAX_BODY = 2000


@dataclass
class Trace:
    operation: str
    op_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    connection_id: int | None = None
    connection_name: str = ""
    snapshot_id: int | None = None
    batch_id: int | None = None
    run_id: int | None = None
    step: str = ""
    sessions: Callable[[], Session] | None = None
    buffer: list[dict[str, Any]] = field(default_factory=list)
    requests: int = 0
    failed_requests: int = 0
    failed: bool = False  # the operation itself failed (kept: the buffer is flushed on the way)

    def event(self, kind: str, outcome: str, **values: Any) -> None:
        self.buffer.append(
            {
                "at": datetime.now(UTC),
                "op_id": self.op_id,
                "operation": self.operation,
                "connection_id": self.connection_id,
                "connection_name": self.connection_name[:128],
                "snapshot_id": self.snapshot_id,
                "batch_id": self.batch_id,
                "run_id": self.run_id,
                "step": self.step[:256],
                "kind": kind,
                "outcome": outcome,
                "method": "",
                "path": "",
                "status": None,
                "duration_ms": None,
                "error_code": "",
                "detail": "",
                "response": "",
                **values,
            }
        )
        if len(self.buffer) >= FLUSH_EVERY:
            self.flush()

    def flush(self) -> None:
        if not self.buffer or self.sessions is None:
            self.buffer.clear()
            return
        rows, self.buffer = self.buffer, []
        try:
            with self.sessions() as session, session.begin():
                session.execute(insert(FmcEvent), rows)
        except Exception:  # the integration log must never break the operation it describes
            log.exception("could not write the FMC integration log")


_current: ContextVar[Trace | None] = ContextVar("fmc_trace", default=None)


def current() -> Trace | None:
    return _current.get()


def set_step(step: str) -> None:
    """Name what the operation is doing now (shown next to every request and the failure)."""
    trace = _current.get()
    if trace is not None:
        trace.step = step


def bind(**values: Any) -> None:
    """Add what became known during the operation (the connection, the snapshot ...)."""
    trace = _current.get()
    if trace is not None:
        for key, value in values.items():
            setattr(trace, key, value)


def _clip(text: str, limit: int) -> str:
    text = scrub_text(text)
    return text if len(text) <= limit else text[:limit] + " …"


def record_request(
    method: str,
    path: str,
    params: Any,
    started: float,
    *,
    status: int | None = None,
    error: BaseException | None = None,
    body: str = "",
) -> None:
    """One HTTP exchange with the FMC (called by FmcSession for every attempt)."""
    trace = _current.get()
    if trace is None:
        return
    query = ""
    if isinstance(params, dict) and params:
        query = "?" + urlencode({k: v for k, v in params.items() if v is not None})
    failed = error is not None or status is None or status >= 400
    trace.requests += 1
    trace.failed_requests += int(failed)
    trace.event(
        "request",
        "error" if failed else "ok",
        method=method[:8],
        path=(path + query)[:512],
        status=status,
        duration_ms=int((time.monotonic() - started) * 1000),
        error_code=type(error).__name__[:64] if error is not None else "",
        detail=_clip(str(error), MAX_DETAIL) if error is not None else "",
        response=_clip(body, MAX_BODY) if failed and body else "",
    )


def note_bad_response(path: str, body: str, reason: str) -> None:
    """A 200 answer the client could not use (invalid JSON, a malformed page)."""
    trace = _current.get()
    if trace is not None:
        trace.event(
            "request",
            "error",
            path=path[:512],
            error_code="unexpected_response",
            detail=_clip(reason, MAX_DETAIL),
            response=_clip(body, MAX_BODY),
        )


def fail(code: str, detail: str) -> None:
    """The operation ended in an error (also for failures it handled and reported itself)."""
    trace = _current.get()
    if trace is not None:
        trace.failed = True
        trace.event("failed", "error", error_code=code[:64], detail=_clip(detail, MAX_DETAIL))


@contextmanager
def tracing(
    operation: str, sessions: Callable[[], Session] | None, **context: Any
) -> Iterator[Trace]:
    """One FMC operation's log scope. Exceptions are recorded and re-raised."""
    trace = Trace(operation=operation, sessions=sessions, **context)
    token = _current.set(trace)
    started = time.monotonic()
    trace.event("started", "ok")
    try:
        yield trace
    except BaseException as exc:
        trace.failed = True
        trace.event(
            "failed",
            "error",
            error_code=str(getattr(exc, "code", type(exc).__name__))[:64],
            detail=_clip(f"{type(exc).__name__}: {exc}", MAX_DETAIL),
        )
        raise
    finally:
        trace.step = ""
        trace.event(
            "finished",
            "error" if trace.failed else "ok",
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=f"{trace.requests} requests, {trace.failed_requests} failed",
        )
        trace.flush()
        _current.reset(token)
        _prune(sessions)


def _prune(sessions: Callable[[], Session] | None) -> None:
    if sessions is None:
        return
    cutoff = datetime.now(UTC) - timedelta(days=RETENTION_DAYS)
    try:
        with sessions() as session, session.begin():
            session.execute(delete(FmcEvent).where(FmcEvent.at < cutoff))
    except Exception:
        log.exception("could not prune the FMC integration log")
