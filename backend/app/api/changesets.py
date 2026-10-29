"""Phase 5: changesets — staged, batched, approved. Writing to the FMC is a separate step."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import StrictModel
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.core.config import get_settings
from app.db.session import get_db
from app.enforce.batching import Conflict, Item, ItemTooLargeError, batch, separate
from app.enforce.executor import rollback_resumable, stale_after_run
from app.enforce.staleness import stale_since
from app.models.assets import ClusterSetting
from app.models.enforce import Batch, Changeset, ChangesetItem
from app.models.inventory import Cluster, ClusterPolicy, Snapshot
from app.models.recommendations import Recommendation, RecommendationDecision
from app.runtime import get_audit
from app.workers import jobs

router = APIRouter(prefix="/api", tags=["changesets"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
OptimizerDep = Annotated[Principal, Depends(require(Permission.CHANGESET_WRITE))]
ApproverDep = Annotated[Principal, Depends(require(Permission.DEPLOY_APPROVE))]
TicketId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,63}$")]


class ChangesetIn(StrictModel):
    snapshot_id: int
    recommendation_ids: Annotated[list[int], Field(min_length=1, max_length=500)]
    title: Annotated[str, Field(min_length=3, max_length=200)]
    ticket_id: TicketId


class BatchOut(BaseModel):
    seq: int
    status: str
    op_count: int
    deploy_limit: int
    clusters: list[str]
    approved_by: str | None
    approved_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    results: list[dict[str, Any]]
    # Undo steps saved for this batch that are not undone yet (a rollback can be resumed).
    undo_pending: int
    rollback_resumable: bool
    # Traffic proof of the plan (None while it is being computed) and of what the FMC held
    # after the writes, checked before deploying.
    proof: dict[str, Any] | None = None
    proof_after: dict[str, Any] | None = None
    changes_acknowledged_by: str | None = None


class ItemOut(BaseModel):
    fingerprint: str
    kind: str
    title: str
    policy_fmc_id: str | None
    batch_seq: int
    op_count: int
    plan: dict[str, Any]


class ChangesetOut(BaseModel):
    id: int
    snapshot_id: int | None
    connection_id: int | None
    title: str
    ticket_id: str
    status: str
    deploy_limit: int
    deploy_limit_verified: bool
    created_by: str
    created_at: datetime
    op_count: int
    item_count: int
    batches: list[BatchOut]


class HeldOut(BaseModel):
    recommendation: int
    title: str
    blocked_by: int  # the staged recommendation touching the same rule / object
    reason: str  # same_rule | same_object | deletes_used


class ChangesetDetail(ChangesetOut):
    items: list[ItemOut]
    # Accepted but left for the next changeset: they touch what a staged one changes.
    held: list[HeldOut] = []


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
            target=target,
            source_ip=client_ip(request),
            details=details,
        ),
    )


def _batch_out(b: Batch) -> BatchOut:
    return BatchOut(
        seq=b.seq,
        status=b.status,
        op_count=b.op_count,
        deploy_limit=b.deploy_limit,
        clusters=b.clusters,
        approved_by=b.approved_by,
        approved_at=b.approved_at,
        started_at=b.started_at,
        finished_at=b.finished_at,
        error=b.error,
        results=b.results,
        undo_pending=sum(1 for step in b.journal if step.get("state") != "undone")
        if b.status != "deployed"
        else 0,
        rollback_resumable=rollback_resumable(
            b, datetime.now(UTC), stale_after_run(get_settings())
        ),
        proof=b.proof,
        proof_after=b.proof_after,
        changes_acknowledged_by=b.changes_acknowledged_by,
    )


def _out(db: Session, cs: Changeset) -> ChangesetOut:
    batches = list(db.scalars(select(Batch).where(Batch.changeset_id == cs.id).order_by(Batch.seq)))
    counts = db.execute(
        select(func.count(), func.coalesce(func.sum(ChangesetItem.op_count), 0)).where(
            ChangesetItem.changeset_id == cs.id
        )
    ).one()
    return ChangesetOut(
        id=cs.id,
        snapshot_id=cs.snapshot_id,
        connection_id=cs.connection_id,
        title=cs.title,
        ticket_id=cs.ticket_id,
        status=cs.status,
        deploy_limit=cs.deploy_limit,
        deploy_limit_verified=cs.deploy_limit_verified,
        created_by=cs.created_by,
        created_at=cs.created_at,
        op_count=int(counts[1]),
        item_count=int(counts[0]),
        batches=[_batch_out(b) for b in batches],
    )


def _conflict(detail: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": detail, **extra})


def _clusters_of(db: Session, snapshot_id: int) -> tuple[dict[str, set[str]], set[str]]:
    by_policy: dict[str, set[str]] = defaultdict(set)
    for cluster_id, policy_id in db.execute(
        select(ClusterPolicy.cluster_fmc_id, ClusterPolicy.policy_fmc_id).where(
            ClusterPolicy.snapshot_id == snapshot_id
        )
    ).all():
        by_policy[policy_id].add(cluster_id)
    every = set(db.scalars(select(Cluster.fmc_id).where(Cluster.snapshot_id == snapshot_id)))
    return by_policy, every


def _item_clusters(
    plan: dict[str, Any], by_policy: dict[str, set[str]], every: set[str]
) -> frozenset[str]:
    """Rule changes affect the clusters governed by the policy; shared objects affect all."""
    clusters: set[str] = set()
    for op in plan.get("ops", []):
        if "policy" in op:
            clusters |= by_policy.get(op["policy"], set())
        else:
            clusters |= every
    return frozenset(clusters or every)


@router.post("/changesets", response_model=ChangesetDetail, status_code=status.HTTP_201_CREATED)
def create_changeset(
    body: ChangesetIn, request: Request, db: DbDep, audit: AuditDep, who: OptimizerDep
) -> ChangesetDetail | JSONResponse:
    """Stage accepted recommendations into a changeset, cut into batches. Nothing is sent."""
    snap = db.get(Snapshot, body.snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    latest = db.scalar(
        select(func.max(Snapshot.id)).where(
            Snapshot.connection_id == snap.connection_id, Snapshot.status == "complete"
        )
    )
    if snap.status != "complete" or latest != snap.id:
        return _conflict("snapshot_outdated", latest=latest)
    stale = stale_since(db, snap)
    if stale is not None:
        # The FMC was changed by this system after the snapshot: plans would drift.
        return _conflict(
            "snapshot_stale",
            changeset=stale["changeset_id"],
            batch=stale["batch"],
            at=stale["at"].isoformat(),
        )
    rows = db.execute(
        select(Recommendation, RecommendationDecision.status)
        .outerjoin(
            RecommendationDecision,
            RecommendationDecision.fingerprint == Recommendation.fingerprint,
        )
        .where(
            Recommendation.snapshot_id == snap.id,
            Recommendation.id.in_(set(body.recommendation_ids)),
        )
    ).all()
    if len(rows) != len(set(body.recommendation_ids)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    not_accepted = [r.id for r, decision in rows if decision != "accepted"]
    if not_accepted:
        return _conflict("not_accepted", recommendations=sorted(not_accepted))
    blocked = {r.id: r.plan.get("blocked", []) for r, _ in rows if not r.plan.get("executable")}
    if blocked:
        return _conflict("not_executable", recommendations=blocked)
    staged = set(
        db.scalars(
            select(ChangesetItem.fingerprint)
            .join(Changeset, Changeset.id == ChangesetItem.changeset_id)
            .where(
                Changeset.status.in_(("open", "in_progress")),
                ChangesetItem.fingerprint.in_([r.fingerprint for r, _ in rows]),
            )
        )
    )
    if staged:
        holders = db.execute(
            select(Changeset.id, Changeset.title)
            .join(ChangesetItem, ChangesetItem.changeset_id == Changeset.id)
            .where(
                Changeset.status.in_(("open", "in_progress")),
                ChangesetItem.fingerprint.in_(staged),
            )
            .distinct()
        ).all()
        return _conflict(
            "already_staged",
            recommendations=sorted(r.id for r, _ in rows if r.fingerprint in staged),
            changesets=[{"id": i, "title": t} for i, t in holders],
        )

    by_policy, every = _clusters_of(db, snap.id)
    recs = {r.fingerprint: r for r, _ in rows}
    items = [
        Item(
            key=r.fingerprint,
            kind=r.kind,
            title=r.title,
            plan=r.plan,
            clusters=_item_clusters(r.plan, by_policy, every),
        )
        for r, _ in sorted(rows, key=lambda x: x[0].id)
    ]
    items, held = separate(items)

    settings = get_settings()
    limits = {s.cluster_fmc_id: s for s in db.scalars(select(ClusterSetting))}

    def limit_of(clusters: set[str]) -> int:
        values = [
            limits[c].deploy_change_limit if c in limits else settings.default_deploy_change_limit
            for c in clusters
        ]
        return min(values) if values else settings.default_deploy_change_limit

    try:
        planned = batch(items, limit_of)
    except ItemTooLargeError as exc:
        return _conflict(
            "item_exceeds_limit",
            recommendation=recs[exc.item.key].id,
            operations=exc.item.op_count,
            limit=exc.limit,
        )
    touched_clusters = set().union(*(set(i.clusters) for i in items))
    cs = Changeset(
        connection_id=snap.connection_id,
        snapshot_id=snap.id,
        title=body.title,
        ticket_id=body.ticket_id,
        status="open",
        deploy_limit=limit_of(touched_clusters),
        deploy_limit_verified=bool(touched_clusters)
        and all(c in limits and limits[c].deploy_limit_verified for c in touched_clusters),
        created_by=who.username,
    )
    db.add(cs)
    db.flush()
    position = 0
    for planned_batch in planned:
        db.add(
            Batch(
                changeset_id=cs.id,
                seq=planned_batch.seq,
                status="pending",
                op_count=planned_batch.op_count,
                deploy_limit=planned_batch.limit,
                clusters=sorted(planned_batch.clusters),
                results=[],
            )
        )
        for item in planned_batch.items:
            position += 1
            rec = recs[item.key]
            db.add(
                ChangesetItem(
                    changeset_id=cs.id,
                    batch_seq=planned_batch.seq,
                    position=position,
                    fingerprint=item.key,
                    kind=item.kind,
                    title=item.title[:512],
                    policy_fmc_id=rec.policy_fmc_id,
                    plan=item.plan,
                    op_count=item.op_count,
                )
            )
    db.flush()
    _audit(
        audit,
        db,
        who,
        request,
        "changeset.create",
        body.title,
        {
            "changeset_id": cs.id,
            "ticket_id": body.ticket_id,
            "snapshot_id": snap.id,
            "recommendations": len(items),
            "held": len(held),
            "batches": len(planned),
        },
    )
    db.commit()
    jobs.enqueue_proof(cs.id, who.username)
    return _detail(db, cs).model_copy(update={"held": [_held(recs, c) for c in held]})


def _held(recs: dict[str, Recommendation], c: Conflict) -> HeldOut:
    return HeldOut(
        recommendation=recs[c.second].id,
        title=recs[c.second].title,
        blocked_by=recs[c.first].id,
        reason=c.reason,
    )


def _detail(db: Session, cs: Changeset) -> ChangesetDetail:
    items = db.scalars(
        select(ChangesetItem)
        .where(ChangesetItem.changeset_id == cs.id)
        .order_by(ChangesetItem.position)
    )
    return ChangesetDetail(
        **_out(db, cs).model_dump(),
        items=[
            ItemOut(
                fingerprint=i.fingerprint,
                kind=i.kind,
                title=i.title,
                policy_fmc_id=i.policy_fmc_id,
                batch_seq=i.batch_seq,
                op_count=i.op_count,
                plan=i.plan,
            )
            for i in items
        ],
    )


@router.get("/changesets", response_model=list[ChangesetOut])
def list_changesets(db: DbDep, _: ReaderDep) -> list[ChangesetOut]:
    return [
        _out(db, cs)
        for cs in db.scalars(select(Changeset).order_by(Changeset.id.desc()).limit(200))
    ]


@router.get("/changesets/{changeset_id}", response_model=ChangesetDetail)
def get_changeset(changeset_id: int, db: DbDep, _: ReaderDep) -> ChangesetDetail:
    cs = db.get(Changeset, changeset_id)
    if cs is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return _detail(db, cs)


class ApproveIn(StrictModel):
    # The approver has seen the flows a behaviour-changing batch changes.
    acknowledge_change: bool = False


@router.post("/changesets/{changeset_id}/batches/{seq}/approve", response_model=ChangesetOut)
def approve_batch(
    changeset_id: int,
    seq: int,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    who: ApproverDep,
    body: ApproveIn | None = None,
) -> ChangesetOut:
    """Approve the next batch. Four eyes: the changeset's author can never approve it.

    The batch's traffic proof must exist: a batch that preserves traffic is approved only with
    no flow changed; one that changes traffic by design needs ``acknowledge_change``.
    """
    cs = db.get(Changeset, changeset_id, with_for_update=True)
    if cs is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if cs.created_by == who.username:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "author_cannot_approve")
    if cs.status not in ("open", "in_progress"):
        raise HTTPException(status.HTTP_409_CONFLICT, "changeset_closed")
    target = db.scalar(select(Batch).where(Batch.changeset_id == cs.id, Batch.seq == seq))
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if target.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "batch_not_pending")
    earlier = db.scalar(
        select(func.count()).where(
            Batch.changeset_id == cs.id, Batch.seq < seq, Batch.status != "deployed"
        )
    )
    if earlier:
        raise HTTPException(status.HTTP_409_CONFLICT, "previous_batch_not_deployed")
    proof = target.proof
    if proof is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "proof_pending")
    changed = int(proof.get("differences", 0))
    if proof.get("behavior") != "changes" and changed:
        raise HTTPException(status.HTTP_409_CONFLICT, "proof_failed")
    if proof.get("behavior") == "changes" and changed:
        if body is None or not body.acknowledge_change:
            raise HTTPException(status.HTTP_409_CONFLICT, "behavior_change_unacknowledged")
        target.changes_acknowledged_by = who.username
    target.status = "approved"
    target.approved_by = who.username
    target.approved_at = datetime.now(UTC)
    _audit(
        audit,
        db,
        who,
        request,
        "changeset.batch_approve",
        cs.title,
        {
            "changeset_id": cs.id,
            "batch": seq,
            "ticket_id": cs.ticket_id,
            "operations": target.op_count,
        },
    )
    db.commit()
    return _out(db, cs)


@router.post(
    "/changesets/{changeset_id}/batches/{seq}/run",
    response_model=ChangesetOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def run_batch(
    changeset_id: int, seq: int, request: Request, db: DbDep, audit: AuditDep, who: ApproverDep
) -> ChangesetOut:
    """Push an approved batch to the FMC and deploy it (asynchronous; rolls back on failure)."""
    cs = db.get(Changeset, changeset_id, with_for_update=True)
    if cs is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if cs.created_by == who.username:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "author_cannot_approve")
    if cs.status not in ("open", "in_progress"):
        raise HTTPException(status.HTTP_409_CONFLICT, "changeset_closed")
    target = db.scalar(select(Batch).where(Batch.changeset_id == cs.id, Batch.seq == seq))
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if target.status != "approved":
        raise HTTPException(status.HTTP_409_CONFLICT, "batch_not_approved")
    _audit(
        audit,
        db,
        who,
        request,
        "changeset.batch_run",
        cs.title,
        {
            "changeset_id": cs.id,
            "batch": seq,
            "ticket_id": cs.ticket_id,
            "operations": target.op_count,
        },
    )
    db.commit()
    jobs.enqueue_batch(target.id, who.username)
    return _out(db, cs)


@router.post(
    "/changesets/{changeset_id}/batches/{seq}/rollback",
    response_model=ChangesetOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def resume_batch_rollback(
    changeset_id: int, seq: int, request: Request, db: DbDep, audit: AuditDep, who: ApproverDep
) -> ChangesetOut:
    """Finish the rollback of a batch that could not be fully undone (asynchronous).

    Only restores the configuration the batch started from, so any approver may run it
    (the author included): it never writes anything that was not there before.
    """
    cs = db.get(Changeset, changeset_id)
    if cs is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    target = db.scalar(
        select(Batch).where(Batch.changeset_id == cs.id, Batch.seq == seq).with_for_update()
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if not rollback_resumable(target, datetime.now(UTC), stale_after_run(get_settings())):
        raise HTTPException(status.HTTP_409_CONFLICT, "nothing_to_undo")
    _audit(
        audit,
        db,
        who,
        request,
        "changeset.batch_rollback",
        cs.title,
        {
            "changeset_id": cs.id,
            "batch": seq,
            "ticket_id": cs.ticket_id,
            "steps": sum(1 for step in target.journal if step.get("state") != "undone"),
        },
    )
    db.commit()
    jobs.enqueue_rollback(target.id, who.username)
    return _out(db, cs)


@router.post("/changesets/{changeset_id}/cancel", response_model=ChangesetOut)
def cancel_changeset(
    changeset_id: int, request: Request, db: DbDep, audit: AuditDep, who: OptimizerDep
) -> ChangesetOut:
    """Cancel what has not run yet (already deployed batches stay deployed). A failed changeset
    can be cancelled too — once no batch is running and no failed batch has writes left to
    undo (finish its rollback first)."""
    cs = db.get(Changeset, changeset_id, with_for_update=True)
    if cs is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if cs.status not in ("open", "in_progress", "failed"):
        raise HTTPException(status.HTTP_409_CONFLICT, "changeset_closed")
    batches = list(db.scalars(select(Batch).where(Batch.changeset_id == cs.id)))
    if any(b.status == "running" for b in batches):
        raise HTTPException(status.HTTP_409_CONFLICT, "batch_running")
    if any(
        b.status == "failed" and any(step.get("state") != "undone" for step in b.journal)
        for b in batches
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "rollback_pending")
    for b in batches:
        if b.status in ("pending", "approved"):
            b.status = "cancelled"
    cs.status = "cancelled"
    _audit(audit, db, who, request, "changeset.cancel", cs.title, {"changeset_id": cs.id})
    db.commit()
    return _out(db, cs)
