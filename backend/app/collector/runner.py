"""Snapshot lifecycle around a collection run.

pending -> running -> complete | failed. At most one active snapshot per FMC
connection; a "running" snapshot whose heartbeat is older than
``collect_stale_minutes`` is considered dead (worker crash) and may be resumed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.chain import AuditEvent, AuditLog
from app.collector.service import Collector, mark
from app.core.config import Settings
from app.core.crypto import SecretBox
from app.core.logging import scrub_text
from app.fmc.adapters import select_adapter
from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError
from app.fmc.probe import server_version
from app.models.fmc import FmcConnection
from app.models.inventory import Snapshot

log = logging.getLogger(__name__)

ACTIVE = ("pending", "running")


class SnapshotBusyError(Exception):
    """Another collection for the same FMC connection is in progress."""


class SnapshotStateError(Exception):
    """The snapshot cannot be (re)started in its current state."""


def is_stale(snapshot: Snapshot, stale_after: timedelta, now: datetime | None = None) -> bool:
    if snapshot.status != "running":
        return False
    reference = snapshot.heartbeat_at or snapshot.started_at or snapshot.created_at
    return (now or datetime.now(UTC)) - reference > stale_after


def request_collection(
    session: Session, connection: FmcConnection, requested_by: str, stale_after: timedelta
) -> Snapshot:
    """Create a pending snapshot (caller commits and enqueues the job)."""
    active = session.scalars(
        select(Snapshot)
        .where(Snapshot.connection_id == connection.id, Snapshot.status.in_(ACTIVE))
        .with_for_update()
    ).all()
    for snap in active:
        if snap.status == "pending" or not is_stale(snap, stale_after):
            raise SnapshotBusyError(f"snapshot {snap.id} is {snap.status}")
        snap.status, snap.error = "failed", "stale"
    snapshot = Snapshot(
        connection_id=connection.id,
        connection_name=connection.name,
        status="pending",
        requested_by=requested_by[:64],
        stats={},
    )
    session.add(snapshot)
    session.flush()
    return snapshot


def prepare_resume(session: Session, snapshot: Snapshot, stale_after: timedelta) -> None:
    if snapshot.status == "failed" or is_stale(snapshot, stale_after):
        snapshot.status, snapshot.error, snapshot.error_detail = "pending", None, None
        return
    raise SnapshotStateError(f"snapshot {snapshot.id} is {snapshot.status}")


async def run_collection(
    snapshot_id: int,
    *,
    sessions: sessionmaker[Session],
    box: SecretBox,
    audit: AuditLog,
    settings: Settings,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    with sessions.begin() as session:
        snap = session.get(Snapshot, snapshot_id, with_for_update=True)
        if snap is None:
            raise SnapshotStateError(f"snapshot {snapshot_id} does not exist")
        if snap.status == "complete":
            return snap.stats
        stale_after = timedelta(minutes=settings.collect_stale_minutes)
        if snap.status == "running" and not is_stale(snap, stale_after):
            raise SnapshotBusyError(f"snapshot {snapshot_id} is already running")
        conn = session.get(FmcConnection, snap.connection_id) if snap.connection_id else None
        now = datetime.now(UTC)
        snap.status, snap.error, snap.error_detail = "running", None, None
        snap.started_at = snap.started_at or now
        snap.heartbeat_at = now
        actor, connection_name = snap.requested_by, snap.connection_name
        if conn is None:
            snap.status, snap.error, snap.finished_at = "failed", "connection_deleted", now
            return {}
        host, port, username, token = conn.host, conn.port, conn.username, conn.password_enc
        context = FmcConnection.password_context(conn.id)
        connection_id = conn.id

    def password_provider() -> bytearray:
        return box.decrypt(token, context)

    try:
        async with FmcSession(
            host=host,
            port=port,
            username=username,
            password_provider=password_provider,
            ssl_context=build_ssl_context(settings.fmc_ca_bundle),
            timeout=settings.fmc_timeout_seconds,
            transport=transport,
            throttle=ThrottlePolicy(
                requests_per_minute=settings.fmc_requests_per_minute,
                concurrency=settings.fmc_concurrency,
            ),
        ) as fmc:
            version = await server_version(fmc)
            adapter = select_adapter(version)
            mark(sessions, snapshot_id, fmc_version=version, domain_uuid=fmc.domain_uuid)
            stats = await Collector(
                snapshot_id=snapshot_id, fmc=fmc, adapter=adapter, sessions=sessions
            ).run()
    except FmcError as exc:
        detail = scrub_text(str(exc))[:500]
        log.warning(
            "collection failed", extra={"snapshot": snapshot_id, "code": exc.code, "detail": detail}
        )
        mark(
            sessions,
            snapshot_id,
            status="failed",
            error=exc.code,
            error_detail=detail,
            finished_at=datetime.now(UTC),
        )
        _audit(
            sessions,
            audit,
            actor,
            "collect.failed",
            connection_name,
            snapshot_id,
            {"error": exc.code},
        )
        return {"ok": False, "error": exc.code}
    except Exception:
        mark(
            sessions,
            snapshot_id,
            status="failed",
            error="internal_error",
            finished_at=datetime.now(UTC),
        )
        _audit(
            sessions,
            audit,
            actor,
            "collect.failed",
            connection_name,
            snapshot_id,
            {"error": "internal_error"},
        )
        raise

    mark(sessions, snapshot_id, status="complete", stats=stats, finished_at=datetime.now(UTC))
    _audit(
        sessions,
        audit,
        actor,
        "collect.complete",
        connection_name,
        snapshot_id,
        {"rules": stats["rules"], "objects": stats["objects"], "clusters": stats["clusters"]},
    )
    with sessions.begin() as session:
        apply_retention(session, connection_id, settings.snapshot_retention)
    return {"ok": True, **stats}


def apply_retention(session: Session, connection_id: int, keep: int) -> int:
    """Delete finished snapshots beyond the newest ``keep`` for a connection."""
    old_ids = session.scalars(
        select(Snapshot.id)
        .where(Snapshot.connection_id == connection_id, Snapshot.status.in_(("complete", "failed")))
        .order_by(Snapshot.created_at.desc(), Snapshot.id.desc())
        .offset(keep)
    ).all()
    if old_ids:
        session.execute(delete(Snapshot).where(Snapshot.id.in_(old_ids)))
    return len(old_ids)


def _audit(
    sessions: sessionmaker[Session],
    audit: AuditLog,
    actor: str,
    action: str,
    target: str,
    snapshot_id: int,
    details: dict[str, Any],
) -> None:
    with sessions.begin() as session:
        audit.record(
            session,
            AuditEvent(
                actor=actor,
                action=action,
                outcome="success" if action.endswith("complete") else "failure",
                target=target,
                details={"snapshot_id": snapshot_id, **details},
            ),
        )
