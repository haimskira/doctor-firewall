"""Background jobs.

Jobs are plain functions with JSON-serialisable arguments. Only functions listed
in :data:`ALLOWED_JOBS` may be executed by a worker (see :mod:`app.workers.worker`).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.analysis.basic import analyze
from app.analysis.recommend import recommend
from app.analysis.semantic import analyze_semantics
from app.collector.runner import SnapshotBusyError, request_collection, run_collection
from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.enforce.batch_proof import prove_changeset
from app.enforce.executor import execute_batch, redis_lock, resume_rollback
from app.models.enforce import Batch, Changeset
from app.models.fmc import FmcConnection
from app.models.inventory import Snapshot
from app.runtime import get_audit, get_redis, get_secretbox
from app.workers import progress
from app.workers.queues import QueueName, get_queue

log = logging.getLogger(__name__)


def _enqueue(
    queue: QueueName,
    func: Any,
    arg: int,
    *,
    kind: str,
    title: str,
    requested_by: str,
    timeout: int,
    snapshot_id: int | None = None,
    batch_id: int | None = None,
    changeset_id: int | None = None,
) -> int:
    """Record the run, queue the job with its run id, and remember the RQ job id."""
    sessions = get_sessionmaker()
    run_id = progress.create_run(
        sessions,
        kind,
        title,
        requested_by,
        snapshot_id=snapshot_id,
        batch_id=batch_id,
        changeset_id=changeset_id,
    )
    job = get_queue(queue, get_redis()).enqueue(func, arg, run_id=run_id, job_timeout=timeout)
    progress.set_rq_job(sessions, run_id, str(job.id))
    return run_id


def _snapshot_title(snapshot_id: int) -> str:
    with get_sessionmaker()() as session:
        snap = session.get(Snapshot, snapshot_id)
        return snap.connection_name if snap is not None else f"#{snapshot_id}"


def _batch_ids(batch_id: int) -> tuple[str, int | None]:
    with get_sessionmaker()() as session:
        batch = session.get(Batch, batch_id)
        cs = session.get(Changeset, batch.changeset_id) if batch is not None else None
        if batch is None or cs is None:
            return f"#{batch_id}", None
        return f"{cs.title} · {batch.seq}", cs.id


def verify_audit_chain(run_id: int | None = None) -> dict[str, object]:
    """Recompute the audit hash chain and publish the head hash as an external anchor."""
    sessions = get_sessionmaker()
    if run_id is None:  # queued by the scheduler: record the run as it starts
        run_id = progress.create_run(sessions, "audit_verify", "audit", "system:scheduler")
    with progress.tracked(sessions, run_id), sessions() as session:
        progress.phase("audit_verify", 0, 100)
        result = get_audit().verify(session)
        if not result.ok:
            progress.fail(f"audit_chain_broken at {result.broken_at_id}")
    payload: dict[str, object] = {
        "ok": result.ok,
        "checked": result.checked,
        "head_id": result.head_id,
        "head_hash": result.head_hash,
        "broken_at_id": result.broken_at_id,
        "reason": result.reason,
    }
    if result.ok:
        log.info("audit chain verified", extra={"audit_anchor": payload})
    else:
        log.error("AUDIT CHAIN INTEGRITY FAILURE", extra={"audit_anchor": payload})
    return payload


def enqueue_collection(snapshot_id: int, requested_by: str) -> int:
    return _enqueue(
        QueueName.COLLECT,
        collect_snapshot,
        snapshot_id,
        kind="collect",
        title=_snapshot_title(snapshot_id),
        requested_by=requested_by,
        timeout=get_settings().collect_job_timeout_seconds,
        snapshot_id=snapshot_id,
    )


def _own_run(kind: str, snapshot_id: int | None = None, batch_id: int | None = None) -> int:
    """A run for a job queued without one (queued before job tracking existed)."""
    title = _snapshot_title(snapshot_id) if snapshot_id is not None else f"#{batch_id}"
    return progress.create_run(
        get_sessionmaker(), kind, title, "system", snapshot_id=snapshot_id, batch_id=batch_id
    )


def collect_snapshot(snapshot_id: int, run_id: int | None = None) -> dict[str, Any]:
    """Collect one snapshot (read-only), then queue its analysis."""
    sessions = get_sessionmaker()
    run_id = run_id if run_id is not None else _own_run("collect", snapshot_id=snapshot_id)
    with progress.tracked(sessions, run_id):
        result = asyncio.run(
            run_collection(
                snapshot_id,
                sessions=sessions,
                box=get_secretbox(),
                audit=get_audit(),
                settings=get_settings(),
            )
        )
        if not result.get("ok"):
            progress.fail(str(result.get("error") or "failed"))
    if result.get("ok"):
        with sessions() as session:
            snap = session.get(Snapshot, snapshot_id)
            requester = snap.requested_by if snap is not None else "system"
        enqueue_analysis(snapshot_id, requester)
    return result


def enqueue_analysis(snapshot_id: int, requested_by: str) -> int:
    return _enqueue(
        QueueName.ANALYSIS,
        analyze_snapshot,
        snapshot_id,
        kind="analyze",
        title=_snapshot_title(snapshot_id),
        requested_by=requested_by,
        timeout=2 * 3600,
        snapshot_id=snapshot_id,
    )


def analyze_snapshot(snapshot_id: int, run_id: int | None = None) -> dict[str, int]:
    sessions = get_sessionmaker()
    run_id = run_id if run_id is not None else _own_run("analyze", snapshot_id=snapshot_id)
    with progress.tracked(sessions, run_id), sessions.begin() as session:
        snapshot = session.get(Snapshot, snapshot_id)
        if snapshot is None or snapshot.status != "complete":
            progress.fail("snapshot_not_complete")
            return {}
        progress.phase("analyze_basic", 0, 12)
        summary = analyze(session, snapshot_id)
        progress.phase("analyze_rules", 12, 55)
        for kind, count in analyze_semantics(session, snapshot_id, get_settings()).items():
            summary[kind] = summary.get(kind, 0) + count
        progress.phase("recommend", 55, 99)
        recommendations = recommend(session, snapshot_id)
        progress.phase("saving", 99, 99)
    log.info(
        "snapshot analysed",
        extra={"snapshot": snapshot_id, "findings": summary, "recommendations": recommendations},
    )
    return summary


def schedule_due_collections() -> list[int]:
    """Start collections for connections whose sync interval has elapsed."""
    settings = get_settings()
    stale_after = timedelta(minutes=settings.collect_stale_minutes)
    started: list[int] = []
    now = datetime.now(UTC)
    with get_sessionmaker()() as session:
        connections = session.scalars(
            select(FmcConnection).where(FmcConnection.sync_interval_minutes.is_not(None))
        ).all()
        for conn in connections:
            interval = timedelta(minutes=conn.sync_interval_minutes or 0)
            last = session.scalar(
                select(func.max(Snapshot.created_at)).where(Snapshot.connection_id == conn.id)
            )
            if last is not None and now - last < interval:
                continue
            try:
                snapshot = request_collection(session, conn, "system:scheduler", stale_after)
            except SnapshotBusyError:
                session.rollback()
                continue
            session.commit()
            enqueue_collection(snapshot.id, "system:scheduler")
            started.append(snapshot.id)
    return started


def enqueue_batch(batch_id: int, requested_by: str) -> int:
    title, changeset_id = _batch_ids(batch_id)
    return _enqueue(
        QueueName.ENFORCE,
        execute_batch_job,
        batch_id,
        kind="batch",
        title=title,
        requested_by=requested_by,
        timeout=get_settings().deploy_timeout_seconds + 3600,
        batch_id=batch_id,
        changeset_id=changeset_id,
    )


def _enforce_outcome(result: dict[str, Any]) -> None:
    if not result.get("ok"):
        progress.fail(str(result.get("detail") or result.get("error") or result.get("status")))


def execute_batch_job(batch_id: int, run_id: int | None = None) -> dict[str, Any]:
    """Apply one approved batch to the FMC (writes, verification, deploy or rollback)."""
    sessions = get_sessionmaker()
    run_id = run_id if run_id is not None else _own_run("batch", batch_id=batch_id)
    with progress.tracked(sessions, run_id):
        result = asyncio.run(
            execute_batch(
                batch_id,
                sessions=sessions,
                box=get_secretbox(),
                audit=get_audit(),
                settings=get_settings(),
                lock=redis_lock(get_redis()),
            )
        )
        _enforce_outcome(result)
    return result


def enqueue_proof(changeset_id: int, requested_by: str) -> int:
    with get_sessionmaker()() as session:
        cs = session.get(Changeset, changeset_id)
        title = cs.title if cs is not None else f"#{changeset_id}"
    return _enqueue(
        QueueName.ANALYSIS,
        prove_changeset_job,
        changeset_id,
        kind="proof",
        title=title,
        requested_by=requested_by,
        timeout=3600,
        changeset_id=changeset_id,
    )


def prove_changeset_job(changeset_id: int, run_id: int | None = None) -> dict[str, Any]:
    """Prove every batch of a changeset (what each does to traffic) and store the reports."""
    sessions = get_sessionmaker()
    if run_id is None:
        run_id = progress.create_run(sessions, "proof", f"#{changeset_id}", "system")
    with progress.tracked(sessions, run_id):
        outcome = prove_changeset(sessions, changeset_id)
    return {"ok": all(outcome.values()), "batches": {str(k): v for k, v in outcome.items()}}


def enqueue_rollback(batch_id: int, requested_by: str) -> int:
    title, changeset_id = _batch_ids(batch_id)
    return _enqueue(
        QueueName.ENFORCE,
        resume_rollback_job,
        batch_id,
        kind="rollback",
        title=title,
        requested_by=requested_by,
        timeout=get_settings().deploy_timeout_seconds + 3600,
        batch_id=batch_id,
        changeset_id=changeset_id,
    )


def resume_rollback_job(batch_id: int, run_id: int | None = None) -> dict[str, Any]:
    """Finish an interrupted rollback from the batch's journal, then re-deploy."""
    sessions = get_sessionmaker()
    run_id = run_id if run_id is not None else _own_run("rollback", batch_id=batch_id)
    with progress.tracked(sessions, run_id):
        result = asyncio.run(
            resume_rollback(
                batch_id,
                sessions=sessions,
                box=get_secretbox(),
                audit=get_audit(),
                settings=get_settings(),
                lock=redis_lock(get_redis()),
            )
        )
        _enforce_outcome(result)
    return result


ALLOWED_JOBS: frozenset[str] = frozenset(
    {
        "app.workers.jobs.execute_batch_job",
        "app.workers.jobs.resume_rollback_job",
        "app.workers.jobs.prove_changeset_job",
        "app.workers.jobs.verify_audit_chain",
        "app.workers.jobs.collect_snapshot",
        "app.workers.jobs.analyze_snapshot",
        "app.workers.jobs.schedule_due_collections",
    }
)
