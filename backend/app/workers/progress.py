"""Progress of background jobs: queued runs, the worker's steps, and how a run ends.

* :func:`create_run` records a run when a job is queued (the API or scheduler that queues it).
* Inside the job, :func:`tracked` makes a :class:`Reporter` current; code anywhere below calls
  :func:`phase` (a named step covering a share of 0-100 %) and :func:`advance` (``done`` of
  ``total`` in that step). Outside a tracked job both are no-ops, so the collector, analysis
  and executor work the same in tests and tools.
* Writes go through their own short transactions (the analysis runs in one long transaction,
  invisible to readers until it commits) and are throttled to about one per second.

Steps are message keys with numeric / short text arguments, never free text from the FMC.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.core.logging import scrub_text
from app.models.jobs import JobRun

WRITE_EVERY_SECONDS = 1.0

_current: ContextVar[Reporter | None] = ContextVar("job_progress", default=None)


def create_run(
    sessions: sessionmaker[Session],
    kind: str,
    title: str,
    requested_by: str,
    *,
    snapshot_id: int | None = None,
    batch_id: int | None = None,
    changeset_id: int | None = None,
) -> int:
    with sessions.begin() as db:
        run = JobRun(
            kind=kind,
            title=title[:256],
            requested_by=requested_by[:64],
            snapshot_id=snapshot_id,
            batch_id=batch_id,
            changeset_id=changeset_id,
            status="queued",
            progress=0,
            step="queued",
            step_args={},
        )
        db.add(run)
        db.flush()
        return run.id


def set_rq_job(sessions: sessionmaker[Session], run_id: int, rq_job_id: str) -> None:
    with sessions.begin() as db:
        run = db.get(JobRun, run_id)
        if run is not None:
            run.rq_job_id = rq_job_id[:64]


class Reporter:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        run_id: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.sessions = sessions
        self.run_id = run_id
        self.clock = clock
        self.low, self.high = 0, 100
        self.step = "starting"
        self.args: dict[str, Any] = {}
        self.progress = 0
        self.failure: str | None = None
        self._written_at = -1e9

    def _write(self, **fields: Any) -> None:
        now = datetime.now(UTC)
        with self.sessions.begin() as db:
            run = db.get(JobRun, self.run_id)
            if run is None:
                return
            for key, value in fields.items():
                setattr(run, key, value)
            run.progress, run.step, run.step_args = self.progress, self.step, dict(self.args)
            run.updated_at = now
        self._written_at = self.clock()

    def start(self) -> None:
        self._write(status="running", started_at=datetime.now(UTC), error=None)

    def phase(self, step: str, low: int, high: int, **args: Any) -> None:
        self.low, self.high = max(self.progress, low), max(low, high)
        self.step, self.args = step, args
        self.progress = self.low
        self._write()

    def advance(self, done: int, total: int, **args: Any) -> None:
        share = 1.0 if total <= 0 else min(1.0, max(0.0, done / total))
        progress = int(self.low + (self.high - self.low) * share)
        self.args = {**args, "done": done, "total": total}
        self.progress = max(self.progress, min(progress, 99))
        if self.clock() - self._written_at >= WRITE_EVERY_SECONDS:
            self._write()

    def fail(self, error: str) -> None:
        """The job ends without success (it may return instead of raising)."""
        self.failure = scrub_text(error)[:512]

    def finish(self) -> None:
        if self.failure is None:
            self.progress, self.step, self.args = 100, "done", {}
        self._write(
            status="failed" if self.failure else "done",
            error=self.failure,
            finished_at=datetime.now(UTC),
        )


def phase(step: str, low: int, high: int, **args: Any) -> None:
    reporter = _current.get()
    if reporter is not None:
        reporter.phase(step, low, high, **args)


def advance(done: int, total: int, **args: Any) -> None:
    reporter = _current.get()
    if reporter is not None:
        reporter.advance(done, total, **args)


def fail(error: str) -> None:
    reporter = _current.get()
    if reporter is not None:
        reporter.fail(error)


@contextmanager
def tracked(sessions: sessionmaker[Session], run_id: int | None) -> Iterator[Reporter | None]:
    """Run a job body with progress reporting (``run_id`` None: an untracked job)."""
    if run_id is None:
        yield None
        return
    reporter = Reporter(sessions, run_id)
    token = _current.set(reporter)
    reporter.start()
    try:
        yield reporter
    except Exception as exc:
        reporter.fail(f"{type(exc).__name__}: {exc}")
        raise
    finally:
        _current.reset(token)
        reporter.finish()
