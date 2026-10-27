"""Change history: every batch that ran, what it changed (before / after), and reverting it."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import StrictModel
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.enforce.revert import later_batches, revert_blocker
from app.models.enforce import Batch, Changeset
from app.runtime import get_audit
from app.workers import jobs

router = APIRouter(prefix="/api", tags=["history"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
ApproverDep = Annotated[Principal, Depends(require(Permission.DEPLOY_APPROVE))]
RAN = ("deployed", "rolled_back", "failed", "reverted")
SKIP = frozenset({"id", "type", "links", "metadata", "version"})


class HistoryEntry(BaseModel):
    changeset_id: int
    title: str
    ticket_id: str
    created_by: str
    snapshot_id: int | None
    seq: int
    status: str
    op_count: int
    approved_by: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    proof: dict[str, Any] | None
    proof_after: dict[str, Any] | None
    revert_blocker: str | None


class FieldChange(BaseModel):
    field: str
    before: str | None
    after: str | None


class Change(BaseModel):
    op: str
    label: str
    what: str  # rule | object
    action: str  # created | changed | deleted
    fields: list[FieldChange]
    undone: bool


def _summary(value: Any) -> str:
    """A readable value: object names and literal values instead of JSON."""
    if value is None:
        return "—"
    if isinstance(value, dict):
        if "objects" in value or "literals" in value:
            names = [str(o.get("name") or o.get("id")) for o in value.get("objects", [])]
            names += [str(x.get("value") or x.get("port") or x) for x in value.get("literals", [])]
            return ", ".join(sorted(names)) or "any"
        if "name" in value:
            return str(value["name"])
        return ", ".join(f"{k}: {_summary(v)}" for k, v in sorted(value.items()) if k not in SKIP)
    if isinstance(value, list):
        return ", ".join(sorted(_summary(v) for v in value))
    return str(value)


def _fields(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[FieldChange]:
    keys = sorted((set(before or {}) | set(after or {})) - SKIP)
    out = []
    for key in keys:
        b = (before or {}).get(key)
        a = (after or {}).get(key)
        if _summary(b) != _summary(a):
            out.append(FieldChange(field=key, before=_summary(b), after=_summary(a)))
    return out


def describe(step: dict[str, Any]) -> Change:
    path = str(step.get("path") or (step.get("find") or {}).get("path") or "")
    what = "rule" if ("rules/" in path or path.endswith("rules")) else "object"
    kind = step.get("undo")
    if kind == "delete":  # the batch created it
        action, before, after = "created", None, step.get("after")
    elif kind == "recreate":  # the batch deleted it
        action, before, after = "deleted", step.get("body"), None
    else:
        action, before, after = "changed", step.get("body"), step.get("after")
    return Change(
        op=str(step.get("op") or ""),
        label=str(
            step.get("label") or step.get("name") or (before or after or {}).get("name") or ""
        ),
        what=what,
        action=action,
        fields=_fields(before, after),
        undone=step.get("state") == "undone",
    )


def _entry(db: Session, b: Batch, cs: Changeset) -> HistoryEntry:
    return HistoryEntry(
        changeset_id=cs.id,
        title=cs.title,
        ticket_id=cs.ticket_id,
        created_by=cs.created_by,
        snapshot_id=cs.snapshot_id,
        seq=b.seq,
        status=b.status,
        op_count=b.op_count,
        approved_by=b.approved_by,
        started_at=b.started_at,
        finished_at=b.finished_at,
        error=b.error,
        proof=b.proof,
        proof_after=b.proof_after,
        revert_blocker=revert_blocker(db, b) if b.status == "deployed" else None,
    )


@router.get("/history", response_model=list[HistoryEntry])
def history(
    db: DbDep,
    _: ReaderDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[HistoryEntry]:
    """Every batch that ran, newest first."""
    rows = db.execute(
        select(Batch, Changeset)
        .join(Changeset, Changeset.id == Batch.changeset_id)
        .where(Batch.status.in_(RAN))
        .order_by(Batch.started_at.desc().nulls_last(), Batch.id.desc())
        .limit(limit)
    ).all()
    return [_entry(db, b, cs) for b, cs in rows]


def _batch(db: Session, changeset_id: int, seq: int) -> tuple[Batch, Changeset]:
    row = db.execute(
        select(Batch, Changeset)
        .join(Changeset, Changeset.id == Batch.changeset_id)
        .where(Batch.changeset_id == changeset_id, Batch.seq == seq)
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return row[0], row[1]


@router.get("/changesets/{changeset_id}/batches/{seq}/changes", response_model=list[Change])
def batch_changes(changeset_id: int, seq: int, db: DbDep, _: ReaderDep) -> list[Change]:
    """What the batch changed, item by item: before and after, field by field."""
    batch, _cs = _batch(db, changeset_id, seq)
    return [describe(step) for step in batch.journal if step.get("state") in ("applied", "undone")]


class RevertToIn(StrictModel):
    changeset_id: int
    seq: int


def _audit(
    audit: AuditLog,
    db: Session,
    who: Principal,
    request: Request,
    action: str,
    target: str,
    details: dict[str, Any],
) -> None:
    audit.record(
        db,
        AuditEvent(
            actor=who.username,
            actor_id=who.user_id,
            action=action,
            outcome="success",
            target=target[:256],
            source_ip=client_ip(request),
            details=details,
        ),
    )


@router.post(
    "/changesets/{changeset_id}/batches/{seq}/revert",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict[str, Any],
)
def revert(
    changeset_id: int, seq: int, request: Request, db: DbDep, audit: AuditDep, who: ApproverDep
) -> dict[str, Any] | JSONResponse:
    """Undo a deployed batch (asynchronous). Later batches on the same FMC go first."""
    batch, cs = _batch(db, changeset_id, seq)
    blocker = revert_blocker(db, batch)
    if blocker is not None:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": blocker, "later": later_batches(db, batch, cs)},
        )
    _audit(
        audit,
        db,
        who,
        request,
        "changeset.batch_revert",
        cs.title,
        {"changeset_id": cs.id, "batch": seq},
    )
    db.commit()
    run_id = jobs.enqueue_revert([batch.id], who.username, f"{cs.title} · {seq}")
    return {"run_id": run_id, "batches": [{"changeset_id": cs.id, "batch": seq}]}


@router.post(
    "/history/revert-to", status_code=status.HTTP_202_ACCEPTED, response_model=dict[str, Any]
)
def revert_to(
    body: RevertToIn, request: Request, db: DbDep, audit: AuditDep, who: ApproverDep
) -> dict[str, Any] | JSONResponse:
    """Back to the moment before a batch: revert it and every batch deployed after it to the
    same FMC, newest first (one job; it stops at the first one that cannot be reverted)."""
    batch, cs = _batch(db, body.changeset_id, body.seq)
    if batch.status != "deployed" or batch.finished_at is None:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT, content={"detail": "not_deployed"}
        )
    rows = db.execute(
        select(Batch, Changeset)
        .join(Changeset, Changeset.id == Batch.changeset_id)
        .where(
            Changeset.connection_id == cs.connection_id,
            Batch.status == "deployed",
            Batch.finished_at >= batch.finished_at,
        )
        .order_by(Batch.finished_at.desc())
    ).all()
    for b, _c in rows:
        reason = revert_blocker(db, b)
        if reason not in (None, "later_batches_first"):
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={"detail": reason, "changeset_id": _c.id, "batch": b.seq},
            )
    plan = [{"changeset_id": c.id, "batch": b.seq} for b, c in rows]
    _audit(
        audit,
        db,
        who,
        request,
        "changeset.revert_to",
        cs.title,
        {"changeset_id": cs.id, "batch": body.seq, "reverting": plan},
    )
    db.commit()
    run_id = jobs.enqueue_revert([b.id for b, _c in rows], who.username, f"{cs.title} · {body.seq}")
    return {"run_id": run_id, "batches": plan}
