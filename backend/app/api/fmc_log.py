"""The FMC integration log (read-only): operations and every request they made to the FMC."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.fmc import FmcEvent

router = APIRouter(prefix="/api/fmc", tags=["fmc-log"])

DbDep = Annotated[Session, Depends(get_db)]
LogReaderDep = Annotated[Principal, Depends(require(Permission.AUDIT_READ))]
Operation = Literal["test", "collect", "batch", "revert", "rollback", "watch"]
Kind = Literal["started", "request", "failed", "finished"]
EXPORT_MAX = 50_000
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_BOM = "﻿"
COLUMNS = (
    "at",
    "op_id",
    "operation",
    "connection_name",
    "snapshot_id",
    "batch_id",
    "step",
    "kind",
    "outcome",
    "method",
    "path",
    "status",
    "duration_ms",
    "error_code",
    "detail",
    "response",
)


class FmcEventOut(BaseModel):
    id: int
    at: datetime
    op_id: str
    operation: str
    connection_id: int | None
    connection_name: str
    snapshot_id: int | None
    batch_id: int | None
    run_id: int | None
    step: str
    kind: str
    outcome: str
    method: str
    path: str
    status: int | None
    duration_ms: int | None
    error_code: str
    detail: str
    response: str


class FmcEventsPage(BaseModel):
    total: int
    offset: int
    rows: list[FmcEventOut]


def _filtered(
    op: str | None,
    operation: Operation | None,
    kind: list[Kind] | None,
    outcome: Literal["ok", "error"] | None,
    connection_id: int | None,
    snapshot_id: int | None,
    batch_id: int | None,
    q: str | None,
) -> Select[Any]:
    query = select(FmcEvent)
    if op:
        query = query.where(FmcEvent.op_id == op)
    if operation:
        query = query.where(FmcEvent.operation == operation)
    if kind:
        query = query.where(FmcEvent.kind.in_(kind))
    if outcome:
        query = query.where(FmcEvent.outcome == outcome)
    if connection_id is not None:
        query = query.where(FmcEvent.connection_id == connection_id)
    if snapshot_id is not None:
        query = query.where(FmcEvent.snapshot_id == snapshot_id)
    if batch_id is not None:
        query = query.where(FmcEvent.batch_id == batch_id)
    if q:
        needle = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(
            or_(
                FmcEvent.path.ilike(needle, escape="\\"),
                FmcEvent.step.ilike(needle, escape="\\"),
                FmcEvent.detail.ilike(needle, escape="\\"),
                FmcEvent.error_code.ilike(needle, escape="\\"),
            )
        )
    return query


OpQuery = Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")]
KindQuery = Annotated[list[Kind] | None, Query(max_length=4)]
TextQuery = Annotated[str | None, Query(max_length=128)]


@router.get("/events", response_model=FmcEventsPage)
def list_events(
    db: DbDep,
    _: LogReaderDep,
    op: OpQuery = None,
    operation: Operation | None = None,
    kind: KindQuery = None,
    outcome: Literal["ok", "error"] | None = None,
    connection_id: int | None = None,
    snapshot_id: int | None = None,
    batch_id: int | None = None,
    q: TextQuery = None,
    offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> FmcEventsPage:
    """Newest first. ``kind=finished`` lists the operations (one row each, with their
    outcome, duration and request counts); ``op=<op_id>`` everything one operation did."""
    query = _filtered(op, operation, kind, outcome, connection_id, snapshot_id, batch_id, q)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(FmcEvent.id.desc()).offset(offset).limit(limit))
    return FmcEventsPage(
        total=total,
        offset=offset,
        rows=[FmcEventOut.model_validate(r, from_attributes=True) for r in rows],
    )


@router.get("/events/export")
def export_events(
    db: DbDep,
    _: LogReaderDep,
    op: OpQuery = None,
    operation: Operation | None = None,
    kind: KindQuery = None,
    outcome: Literal["ok", "error"] | None = None,
    connection_id: int | None = None,
    snapshot_id: int | None = None,
    batch_id: int | None = None,
    q: TextQuery = None,
) -> Response:
    """The same filters as a CSV file (oldest first, at most 50,000 rows) to send onwards."""
    query = _filtered(op, operation, kind, outcome, connection_id, snapshot_id, batch_id, q)
    newest = db.scalars(query.order_by(FmcEvent.id.desc()).limit(EXPORT_MAX)).all()
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for event in reversed(newest):
        cells = []
        for column in COLUMNS:
            value = getattr(event, column)
            text = value.isoformat() if isinstance(value, datetime) else str(value or "")
            cells.append("'" + text if text.startswith(_FORMULA_PREFIXES) else text)
        writer.writerow(cells)
    return Response(
        _BOM + out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="fmc-log.csv"'},
    )
