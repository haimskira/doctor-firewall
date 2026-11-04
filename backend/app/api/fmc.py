"""FMC connection management (admin). Credentials are write-only through the API."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import Sequence, select
from sqlalchemy.orm import Session

from app.api.schemas import (
    FmcConnectionCreate,
    FmcConnectionResponse,
    FmcConnectionUpdate,
    FmcTestResponse,
)
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.core.config import get_settings
from app.core.crypto import SecretBox
from app.db.session import get_db
from app.fmc.client import build_ssl_context
from app.fmc.errors import FmcError
from app.fmc.probe import probe
from app.models.enforce import Batch, Changeset
from app.models.fmc import FmcConnection
from app.models.inventory import Snapshot
from app.runtime import get_audit, get_secretbox

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fmc/connections", tags=["fmc"])

# Sequence behind fmc_connections.id (PostgreSQL SERIAL naming).
_ID_SEQUENCE = Sequence("fmc_connections_id_seq")

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
BoxDep = Annotated[SecretBox, Depends(get_secretbox)]
AdminDep = Annotated[Principal, Depends(require(Permission.FMC_MANAGE))]


def _to_response(conn: FmcConnection) -> FmcConnectionResponse:
    return FmcConnectionResponse(
        id=conn.id,
        name=conn.name,
        host=conn.host,
        port=conn.port,
        username=conn.username,
        domain_uuid=conn.domain_uuid,
        server_version=conn.server_version,
        last_test_at=conn.last_test_at,
        last_test_ok=conn.last_test_ok,
        sync_interval_minutes=conn.sync_interval_minutes,
    )


def _get(db: Session, connection_id: int) -> FmcConnection:
    conn = db.get(FmcConnection, connection_id)
    if conn is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return conn


def _audit(
    audit: AuditLog,
    db: Session,
    admin: Principal,
    request: Request,
    action: str,
    target: str,
    outcome: str = "success",
    details: dict[str, object] | None = None,
) -> None:
    audit.record(
        db,
        AuditEvent(
            actor=admin.username,
            actor_id=admin.user_id,
            action=action,
            outcome="success" if outcome == "success" else "failure",
            target=target,
            source_ip=client_ip(request),
            details=details or {},
        ),
    )


def _in_use(db: Session, connection_id: int) -> bool:
    """Work that still needs this connection: an open or running changeset, a running batch or
    a failed one with undo steps left, or a collection under way."""
    if db.scalar(
        select(Changeset.id)
        .where(
            Changeset.connection_id == connection_id,
            Changeset.status.in_(("open", "in_progress")),
        )
        .limit(1)
    ):
        return True
    for batch_status, journal in db.execute(
        select(Batch.status, Batch.journal)
        .join(Changeset, Changeset.id == Batch.changeset_id)
        .where(
            Changeset.connection_id == connection_id,
            Batch.status.in_(("running", "failed")),
        )
    ):
        if batch_status == "running" or any(
            step.get("state") != "undone" for step in journal or []
        ):
            return True
    return (
        db.scalar(
            select(Snapshot.id)
            .where(
                Snapshot.connection_id == connection_id,
                Snapshot.status.in_(("pending", "running")),
            )
            .limit(1)
        )
        is not None
    )


@router.get("", response_model=list[FmcConnectionResponse])
def list_connections(db: DbDep, _: AdminDep) -> list[FmcConnectionResponse]:
    return [_to_response(c) for c in db.scalars(select(FmcConnection).order_by(FmcConnection.id))]


@router.post("", response_model=FmcConnectionResponse, status_code=status.HTTP_201_CREATED)
def create_connection(
    body: FmcConnectionCreate,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    box: BoxDep,
    admin: AdminDep,
) -> FmcConnectionResponse:
    if db.scalar(select(FmcConnection.id).where(FmcConnection.name == body.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "name_taken")
    # Reserve the id first: the ciphertext is bound to it (AES-GCM associated data).
    conn_id = db.scalar(select(_ID_SEQUENCE.next_value()))
    if conn_id is None:  # pragma: no cover - nextval always returns a value
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error")
    conn = FmcConnection(
        id=conn_id,
        name=body.name,
        host=body.host,
        port=body.port,
        username=body.username,
        sync_interval_minutes=body.sync_interval_minutes,
        password_enc=box.encrypt(body.password.encode(), FmcConnection.password_context(conn_id)),
    )
    db.add(conn)
    _audit(
        audit,
        db,
        admin,
        request,
        "fmc.connection.create",
        conn.name,
        details={"host": conn.host, "port": conn.port, "username": conn.username},
    )
    db.commit()
    return _to_response(conn)


@router.patch("/{connection_id}", response_model=FmcConnectionResponse)
def update_connection(
    connection_id: int,
    body: FmcConnectionUpdate,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    box: BoxDep,
    admin: AdminDep,
) -> FmcConnectionResponse:
    conn = _get(db, connection_id)
    if (
        body.name is not None
        and body.name != conn.name
        and db.scalar(
            select(FmcConnection.id).where(
                FmcConnection.name == body.name, FmcConnection.id != conn.id
            )
        )
        is not None
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "name_taken")
    moved = any(
        getattr(body, field) is not None and getattr(body, field) != getattr(conn, field)
        for field in ("host", "port", "username")
    )
    if moved and body.password is None:
        # The stored password belongs to this host and account: it is never sent elsewhere.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "password_required")
    changed: list[str] = []
    for field in ("name", "host", "port", "username"):
        value = getattr(body, field)
        if value is not None and value != getattr(conn, field):
            setattr(conn, field, value)
            changed.append(field)
    if body.disable_sync and conn.sync_interval_minutes is not None:
        conn.sync_interval_minutes = None
        changed.append("sync_interval_minutes")
    elif body.sync_interval_minutes is not None and (
        body.sync_interval_minutes != conn.sync_interval_minutes
    ):
        conn.sync_interval_minutes = body.sync_interval_minutes
        changed.append("sync_interval_minutes")
    if body.password is not None:
        conn.password_enc = box.encrypt(
            body.password.encode(), FmcConnection.password_context(conn.id)
        )
        changed.append("password")
    if set(changed) & {"name", "host", "port", "username", "password"}:
        # Connection identity changed: the last test result no longer applies.
        conn.last_test_ok = None
    if changed:
        _audit(
            audit,
            db,
            admin,
            request,
            "fmc.connection.update",
            conn.name,
            details={"fields": changed},
        )
    db.commit()
    return _to_response(conn)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(
    connection_id: int, request: Request, db: DbDep, audit: AuditDep, admin: AdminDep
) -> None:
    conn = _get(db, connection_id)
    if _in_use(db, conn.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "connection_in_use")
    name = conn.name
    db.delete(conn)
    _audit(audit, db, admin, request, "fmc.connection.delete", name)
    db.commit()


@router.post("/{connection_id}/test", response_model=FmcTestResponse)
def test_connection(
    connection_id: int,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    box: BoxDep,
    admin: AdminDep,
) -> FmcTestResponse:
    """Read-only check: token → server version → revoke. Nothing is written to the FMC."""
    conn = _get(db, connection_id)
    settings = get_settings()
    context = FmcConnection.password_context(conn.id)
    token = conn.password_enc

    def password_provider() -> bytearray:
        return box.decrypt(token, context)

    result = FmcTestResponse(ok=False)
    try:
        ssl_context = build_ssl_context(settings.fmc_ca_bundle)
        # Sync endpoint runs in a worker thread, so a private event loop is safe here.
        probed = asyncio.run(
            probe(
                host=conn.host,
                port=conn.port,
                username=conn.username,
                password_provider=password_provider,
                ssl_context=ssl_context,
                timeout=settings.fmc_timeout_seconds,
            )
        )
        result = FmcTestResponse(
            ok=True, server_version=probed.server_version, domain_uuid=probed.domain_uuid
        )
        conn.domain_uuid = probed.domain_uuid
        conn.server_version = probed.server_version
    except FmcError as exc:
        log.warning(
            "FMC connection test failed",
            extra={"connection": conn.name, "code": exc.code, "error": str(exc)},
        )
        result = FmcTestResponse(ok=False, error=exc.code)

    conn.last_test_at = datetime.now(UTC)
    conn.last_test_ok = result.ok
    _audit(
        audit,
        db,
        admin,
        request,
        "fmc.connection.test",
        conn.name,
        outcome="success" if result.ok else "failure",
        details={"error": result.error} if result.error else {},
    )
    db.commit()
    return result
