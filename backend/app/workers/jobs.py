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
from app.enforce.executor import execute_batch, redis_lock, resume_rollback
from app.models.fmc import FmcConnection
from app.models.inventory import Snapshot
from app.runtime import get_audit, get_redis, get_secretbox
from app.workers.queues import QueueName, get_queue

log = logging.getLogger(__name__)


def verify_audit_chain() -> dict[str, object]:
    """Recompute the audit hash chain and publish the head hash as an external anchor."""
    with get_sessionmaker()() as session:
        result = get_audit().verify(session)
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


def enqueue_collection(snapshot_id: int) -> None:
    get_queue(QueueName.COLLECT, get_redis()).enqueue(
        collect_snapshot, snapshot_id, job_timeout=get_settings().collect_job_timeout_seconds
    )


def collect_snapshot(snapshot_id: int) -> dict[str, Any]:
    """Collect one snapshot (read-only), then queue its analysis."""
    result = asyncio.run(
        run_collection(
            snapshot_id,
            sessions=get_sessionmaker(),
            box=get_secretbox(),
            audit=get_audit(),
            settings=get_settings(),
        )
    )
    if result.get("ok"):
        enqueue_analysis(snapshot_id)
    return result


def enqueue_analysis(snapshot_id: int) -> None:
    get_queue(QueueName.ANALYSIS, get_redis()).enqueue(
        analyze_snapshot, snapshot_id, job_timeout=2 * 3600
    )


def analyze_snapshot(snapshot_id: int) -> dict[str, int]:
    with get_sessionmaker().begin() as session:
        snapshot = session.get(Snapshot, snapshot_id)
        if snapshot is None or snapshot.status != "complete":
            return {}
        summary = analyze(session, snapshot_id)
        for kind, count in analyze_semantics(session, snapshot_id, get_settings()).items():
            summary[kind] = summary.get(kind, 0) + count
        recommendations = recommend(session, snapshot_id)
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
            enqueue_collection(snapshot.id)
            started.append(snapshot.id)
    return started


def enqueue_batch(batch_id: int) -> None:
    settings = get_settings()
    get_queue(QueueName.ENFORCE, get_redis()).enqueue(
        execute_batch_job, batch_id, job_timeout=settings.deploy_timeout_seconds + 3600
    )


def execute_batch_job(batch_id: int) -> dict[str, Any]:
    """Apply one approved batch to the FMC (writes, verification, deploy or rollback)."""
    return asyncio.run(
        execute_batch(
            batch_id,
            sessions=get_sessionmaker(),
            box=get_secretbox(),
            audit=get_audit(),
            settings=get_settings(),
            lock=redis_lock(get_redis()),
        )
    )


def enqueue_rollback(batch_id: int) -> None:
    settings = get_settings()
    get_queue(QueueName.ENFORCE, get_redis()).enqueue(
        resume_rollback_job, batch_id, job_timeout=settings.deploy_timeout_seconds + 3600
    )


def resume_rollback_job(batch_id: int) -> dict[str, Any]:
    """Finish an interrupted rollback from the batch's journal, then re-deploy."""
    return asyncio.run(
        resume_rollback(
            batch_id,
            sessions=get_sessionmaker(),
            box=get_secretbox(),
            audit=get_audit(),
            settings=get_settings(),
            lock=redis_lock(get_redis()),
        )
    )


ALLOWED_JOBS: frozenset[str] = frozenset(
    {
        "app.workers.jobs.execute_batch_job",
        "app.workers.jobs.resume_rollback_job",
        "app.workers.jobs.verify_audit_chain",
        "app.workers.jobs.collect_snapshot",
        "app.workers.jobs.analyze_snapshot",
        "app.workers.jobs.schedule_due_collections",
    }
)
