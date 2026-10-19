"""Snapshots and the collected inventory (read-only views + collection triggers)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import Select, func, literal, select
from sqlalchemy.orm import Session

from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.collector.runner import (
    SnapshotBusyError,
    SnapshotStateError,
    prepare_resume,
    request_collection,
)
from app.core.config import get_settings
from app.db.session import get_db
from app.models.fmc import FmcConnection
from app.models.inventory import (
    Bgp,
    Cluster,
    Finding,
    FwObject,
    GroupMember,
    Interface,
    Policy,
    Route,
    Rule,
    RuleRef,
    Snapshot,
)
from app.runtime import get_audit
from app.workers import jobs

router = APIRouter(prefix="/api", tags=["inventory"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
CollectorDep = Annotated[Principal, Depends(require(Permission.COLLECT_RUN))]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
FmcIdPath = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
SearchQuery = Annotated[str | None, Query(max_length=128)]
Offset = Annotated[int, Query(ge=0, le=10_000_000)]

MAX_ANCESTOR_DEPTH = 32


# ------------------------------------------------------------------ schemas


class SnapshotOut(BaseModel):
    id: int
    connection_id: int | None
    connection_name: str
    status: str
    requested_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    analyzed_at: datetime | None
    fmc_version: str | None
    error: str | None
    error_detail: str | None
    stats: dict[str, Any]


class ClusterOut(BaseModel):
    fmc_id: str
    name: str
    kind: str
    sw_version: str
    model: str
    members: list[dict[str, Any]]
    policy_fmc_id: str | None
    policy_name: str | None
    rule_count: int


class RefOut(BaseModel):
    id: str | None = None
    name: str = ""
    kind: str | None = None
    literal: str | None = None


class RuleOut(BaseModel):
    id: str
    index: int
    section: str
    category: str
    name: str
    enabled: bool
    action: str
    hit_count: int | None
    last_hit: datetime | None
    ips_policy: str | None
    file_policy: str | None
    log_begin: bool
    log_end: bool
    refs: dict[str, list[RefOut]]


class RulesPage(BaseModel):
    policy_fmc_id: str
    policy_name: str
    categories: list[str]
    total: int
    offset: int
    rows: list[RuleOut]


class ObjectOut(BaseModel):
    id: str
    name: str
    kind: str
    fmc_type: str
    value: str | None
    stub: bool
    rule_refs: int
    member_of: int


class ObjectsPage(BaseModel):
    total: int
    offset: int
    rows: list[ObjectOut]


class EdgeOut(BaseModel):
    group_id: str
    group_name: str
    child_id: str
    depth: int


class UsageOut(BaseModel):
    policy_fmc_id: str
    rule_id: str
    rule_index: int
    rule_name: str
    field: str
    via_id: str
    via_name: str


class ObjectDetail(BaseModel):
    object: ObjectOut
    attrs: dict[str, Any]
    members: list[RefOut]
    member_of: list[EdgeOut]
    used_by: list[UsageOut]
    used_by_total: int


class FindingOut(BaseModel):
    id: int
    kind: str
    severity: str
    policy_fmc_id: str | None
    title: str
    details: dict[str, Any]


class FindingsPage(BaseModel):
    total: int
    offset: int
    summary: dict[str, dict[str, int]]
    rows: list[FindingOut]


class NetworkOut(BaseModel):
    interfaces: list[dict[str, Any]]
    routes: list[dict[str, Any]]
    bgp: list[dict[str, Any]]


# ------------------------------------------------------------------ helpers


def _snapshot_out(s: Snapshot) -> SnapshotOut:
    return SnapshotOut(
        id=s.id,
        connection_id=s.connection_id,
        connection_name=s.connection_name,
        status=s.status,
        requested_by=s.requested_by,
        created_at=s.created_at,
        started_at=s.started_at,
        finished_at=s.finished_at,
        analyzed_at=s.analyzed_at,
        fmc_version=s.fmc_version,
        error=s.error,
        error_detail=s.error_detail,
        stats=s.stats,
    )


def _snapshot(db: Session, snapshot_id: int) -> Snapshot:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return snap


def _search(column: Any, q: str | None) -> Any:
    return func.lower(column).contains(q.lower(), autoescape=True) if q else None


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


# ------------------------------------------------------------------ snapshots


class ConnectionSummary(BaseModel):
    id: int
    name: str
    sync_interval_minutes: int | None


@router.get("/connections", response_model=list[ConnectionSummary])
def list_connection_names(db: DbDep, _: ReaderDep) -> list[ConnectionSummary]:
    """Names only (no host, user or credentials) so non-admins can pick what to pull."""
    return [
        ConnectionSummary(id=c.id, name=c.name, sync_interval_minutes=c.sync_interval_minutes)
        for c in db.scalars(select(FmcConnection).order_by(FmcConnection.name))
    ]


@router.post(
    "/fmc/connections/{connection_id}/collect",
    response_model=SnapshotOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def start_collection(
    connection_id: int, request: Request, db: DbDep, audit: AuditDep, who: CollectorDep
) -> SnapshotOut:
    """Start a read-only pull of the FMC configuration into a new snapshot."""
    conn = db.get(FmcConnection, connection_id)
    if conn is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    stale = timedelta(minutes=get_settings().collect_stale_minutes)
    try:
        snap = request_collection(db, conn, who.username, stale)
    except SnapshotBusyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "collection_in_progress") from exc
    _audit(audit, db, who, request, "collect.request", conn.name, {"snapshot_id": snap.id})
    db.commit()
    jobs.enqueue_collection(snap.id)
    return _snapshot_out(snap)


@router.post(
    "/snapshots/{snapshot_id}/resume",
    response_model=SnapshotOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def resume_collection(
    snapshot_id: int, request: Request, db: DbDep, audit: AuditDep, who: CollectorDep
) -> SnapshotOut:
    """Resume a failed (or stale) collection from its last checkpoint."""
    snap = db.get(Snapshot, snapshot_id, with_for_update=True)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    try:
        prepare_resume(db, snap, timedelta(minutes=get_settings().collect_stale_minutes))
    except SnapshotStateError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "not_resumable") from exc
    _audit(
        audit, db, who, request, "collect.resume", snap.connection_name, {"snapshot_id": snap.id}
    )
    db.commit()
    jobs.enqueue_collection(snap.id)
    return _snapshot_out(snap)


@router.get("/snapshots", response_model=list[SnapshotOut])
def list_snapshots(
    db: DbDep,
    _: ReaderDep,
    connection_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[SnapshotOut]:
    query = select(Snapshot).order_by(Snapshot.created_at.desc(), Snapshot.id.desc()).limit(limit)
    if connection_id is not None:
        query = query.where(Snapshot.connection_id == connection_id)
    return [_snapshot_out(s) for s in db.scalars(query)]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
def get_snapshot(snapshot_id: int, db: DbDep, _: ReaderDep) -> SnapshotOut:
    return _snapshot_out(_snapshot(db, snapshot_id))


@router.get("/snapshots/{snapshot_id}/clusters", response_model=list[ClusterOut])
def list_clusters(snapshot_id: int, db: DbDep, _: ReaderDep) -> list[ClusterOut]:
    _snapshot(db, snapshot_id)
    rows = db.execute(
        select(Cluster, Policy.name, Policy.rule_count)
        .outerjoin(
            Policy,
            (Policy.snapshot_id == Cluster.snapshot_id) & (Policy.fmc_id == Cluster.policy_fmc_id),
        )
        .where(Cluster.snapshot_id == snapshot_id)
        .order_by(Cluster.name)
    )
    return [
        ClusterOut(
            fmc_id=c.fmc_id,
            name=c.name,
            kind=c.kind,
            sw_version=c.sw_version,
            model=c.model,
            members=c.members,
            policy_fmc_id=c.policy_fmc_id,
            policy_name=pname,
            rule_count=count or 0,
        )
        for c, pname, count in rows
    ]


# ------------------------------------------------------------------ rulebase


@router.get("/snapshots/{snapshot_id}/policies/{policy_id}/rules", response_model=RulesPage)
def list_rules(
    snapshot_id: int,
    policy_id: FmcIdPath,
    db: DbDep,
    _: ReaderDep,
    offset: Offset = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    q: SearchQuery = None,
) -> RulesPage:
    """Rules exactly as in the FMC: original order, with section and category."""
    policy = db.scalar(
        select(Policy).where(Policy.snapshot_id == snapshot_id, Policy.fmc_id == policy_id)
    )
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    base = select(Rule).where(Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id == policy_id)
    if q:
        by_ref = select(RuleRef.rule_id).where(
            RuleRef.snapshot_id == snapshot_id,
            func.lower(
                func.coalesce(RuleRef.object_name, "") + " " + func.coalesce(RuleRef.literal, "")
            ).contains(q.lower(), autoescape=True),
        )
        base = base.where(_search(Rule.name, q) | Rule.id.in_(by_ref))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rules = list(db.scalars(base.order_by(Rule.rule_index).offset(offset).limit(limit)))
    refs: dict[int, dict[str, list[RefOut]]] = defaultdict(lambda: defaultdict(list))
    if rules:
        for rule_id, field, oid, oname, okind, lit in db.execute(
            select(
                RuleRef.rule_id,
                RuleRef.field,
                RuleRef.object_fmc_id,
                RuleRef.object_name,
                FwObject.kind,
                RuleRef.literal,
            )
            .outerjoin(
                FwObject,
                (FwObject.snapshot_id == RuleRef.snapshot_id)
                & (FwObject.fmc_id == RuleRef.object_fmc_id),
            )
            .where(RuleRef.rule_id.in_([r.id for r in rules]))
            .order_by(RuleRef.id)
        ):
            refs[rule_id][field].append(RefOut(id=oid, name=oname, kind=okind, literal=lit))
    return RulesPage(
        policy_fmc_id=policy.fmc_id,
        policy_name=policy.name,
        categories=policy.categories,
        total=total,
        offset=offset,
        rows=[
            RuleOut(
                id=r.fmc_id,
                index=r.rule_index,
                section=r.section,
                category=r.category,
                name=r.name,
                enabled=r.enabled,
                action=r.action,
                hit_count=r.hit_count,
                last_hit=r.last_hit,
                ips_policy=r.ips_policy,
                file_policy=r.file_policy,
                log_begin=r.log_begin,
                log_end=r.log_end,
                refs=dict(refs[r.id]),
            )
            for r in rules
        ],
    )


# ------------------------------------------------------------------ objects


def _object_rows(snapshot_id: int) -> Select[Any]:
    rule_refs = (
        select(func.count(RuleRef.id))
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id == FwObject.fmc_id)
        .scalar_subquery()
    )
    member_of = (
        select(func.count(GroupMember.id))
        .where(GroupMember.snapshot_id == snapshot_id, GroupMember.member_fmc_id == FwObject.fmc_id)
        .scalar_subquery()
    )
    return select(FwObject, rule_refs.label("rule_refs"), member_of.label("member_of")).where(
        FwObject.snapshot_id == snapshot_id
    )


def _object_out(o: FwObject, rule_refs: int, member_of: int) -> ObjectOut:
    return ObjectOut(
        id=o.fmc_id,
        name=o.name,
        kind=o.kind,
        fmc_type=o.fmc_type,
        value=o.value,
        stub=o.stub,
        rule_refs=rule_refs,
        member_of=member_of,
    )


@router.get("/snapshots/{snapshot_id}/objects", response_model=ObjectsPage)
def list_objects(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    kind: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    q: SearchQuery = None,
    offset: Offset = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> ObjectsPage:
    _snapshot(db, snapshot_id)
    query = _object_rows(snapshot_id)
    if kind:
        query = query.where(FwObject.kind == kind)
    if q:
        query = query.where(
            _search(FwObject.name, q) | _search(func.coalesce(FwObject.value, ""), q)
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(query.order_by(FwObject.name, FwObject.fmc_id).offset(offset).limit(limit))
    return ObjectsPage(
        total=total, offset=offset, rows=[_object_out(o, rr, mo) for o, rr, mo in rows]
    )


def _ancestors(db: Session, snapshot_id: int, object_id: str) -> list[tuple[str, str, int]]:
    """(group, child, depth) edges of every group containing the object, transitively."""
    base = select(
        GroupMember.group_fmc_id.label("gid"),
        GroupMember.member_fmc_id.label("child"),
        literal(1).label("depth"),
    ).where(GroupMember.snapshot_id == snapshot_id, GroupMember.member_fmc_id == object_id)
    anc = base.cte("ancestors", recursive=True)
    step = (
        select(GroupMember.group_fmc_id, GroupMember.member_fmc_id, anc.c.depth + 1)
        .join(anc, GroupMember.member_fmc_id == anc.c.gid)
        .where(GroupMember.snapshot_id == snapshot_id, anc.c.depth < MAX_ANCESTOR_DEPTH)
    )
    anc = anc.union(step)
    rows = db.execute(
        select(anc.c.gid, anc.c.child, func.min(anc.c.depth))
        .group_by(anc.c.gid, anc.c.child)
        .order_by(func.min(anc.c.depth))
    )
    return [(g, c, d) for g, c, d in rows]


@router.get("/snapshots/{snapshot_id}/objects/{object_id}", response_model=ObjectDetail)
def object_detail(
    snapshot_id: int,
    object_id: FmcIdPath,
    db: DbDep,
    _: ReaderDep,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> ObjectDetail:
    """Where-used (rules, directly or through any containing group) and membership."""
    row = db.execute(_object_rows(snapshot_id).where(FwObject.fmc_id == object_id)).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    obj, rule_refs, member_of = row
    members = [
        RefOut(id=mid, name=mname, kind=okind, literal=lit)
        for mid, mname, okind, lit in db.execute(
            select(
                GroupMember.member_fmc_id,
                GroupMember.member_name,
                FwObject.kind,
                GroupMember.literal,
            )
            .outerjoin(
                FwObject,
                (FwObject.snapshot_id == GroupMember.snapshot_id)
                & (FwObject.fmc_id == GroupMember.member_fmc_id),
            )
            .where(GroupMember.snapshot_id == snapshot_id, GroupMember.group_fmc_id == object_id)
            .order_by(GroupMember.id)
        )
    ]
    edges = _ancestors(db, snapshot_id, object_id)
    group_ids = {g for g, _, _ in edges}
    names = (
        dict(
            db.execute(
                select(FwObject.fmc_id, FwObject.name).where(
                    FwObject.snapshot_id == snapshot_id,
                    FwObject.fmc_id.in_(group_ids | {object_id}),
                )
            ).all()
        )
        if group_ids or object_id
        else {}
    )
    via_ids = group_ids | {object_id}
    usage_query = (
        select(
            Rule.policy_fmc_id,
            Rule.fmc_id,
            Rule.rule_index,
            Rule.name,
            RuleRef.field,
            RuleRef.object_fmc_id,
        )
        .join(RuleRef, RuleRef.rule_id == Rule.id)
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id.in_(via_ids))
    )
    total = db.scalar(select(func.count()).select_from(usage_query.subquery())) or 0
    used_by = [
        UsageOut(
            policy_fmc_id=p,
            rule_id=rid,
            rule_index=idx,
            rule_name=rname,
            field=fld,
            via_id=via or "",
            via_name=names.get(via or "", ""),
        )
        for p, rid, idx, rname, fld, via in db.execute(
            usage_query.order_by(Rule.policy_fmc_id, Rule.rule_index).limit(limit)
        )
    ]
    return ObjectDetail(
        object=_object_out(obj, rule_refs, member_of),
        attrs=obj.attrs,
        members=members,
        member_of=[
            EdgeOut(group_id=g, group_name=names.get(g, ""), child_id=c, depth=d)
            for g, c, d in edges
        ],
        used_by=used_by,
        used_by_total=total,
    )


# ------------------------------------------------------------------ findings & network


@router.get("/snapshots/{snapshot_id}/findings", response_model=FindingsPage)
def list_findings(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    kind: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    severity: Annotated[str | None, Query(pattern=r"^(info|low|medium|high)$")] = None,
    policy_id: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")] = None,
    offset: Offset = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> FindingsPage:
    _snapshot(db, snapshot_id)
    query = select(Finding).where(Finding.snapshot_id == snapshot_id)
    if kind:
        query = query.where(Finding.kind == kind)
    if severity:
        query = query.where(Finding.severity == severity)
    if policy_id:
        query = query.where(Finding.policy_fmc_id == policy_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    summary: dict[str, dict[str, int]] = defaultdict(dict)
    for k, sev, n in db.execute(
        select(Finding.kind, Finding.severity, func.count())
        .where(Finding.snapshot_id == snapshot_id)
        .group_by(Finding.kind, Finding.severity)
    ):
        summary[k][sev] = n
    severity_order = func.array_position(
        literal(["high", "medium", "low", "info"]), Finding.severity
    )
    rows = db.scalars(
        query.order_by(severity_order, Finding.kind, Finding.id).offset(offset).limit(limit)
    )
    return FindingsPage(
        total=total,
        offset=offset,
        summary=dict(summary),
        rows=[
            FindingOut(
                id=f.id,
                kind=f.kind,
                severity=f.severity,
                policy_fmc_id=f.policy_fmc_id,
                title=f.title,
                details=f.details,
            )
            for f in rows
        ],
    )


@router.get("/snapshots/{snapshot_id}/clusters/{cluster_id}/network", response_model=NetworkOut)
def cluster_network(snapshot_id: int, cluster_id: FmcIdPath, db: DbDep, _: ReaderDep) -> NetworkOut:
    exists = db.scalar(
        select(Cluster.id).where(Cluster.snapshot_id == snapshot_id, Cluster.fmc_id == cluster_id)
    )
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    zone_names = dict(
        db.execute(
            select(FwObject.fmc_id, FwObject.name).where(
                FwObject.snapshot_id == snapshot_id, FwObject.kind == "zone"
            )
        ).all()
    )
    interfaces = [
        {
            "name": i.name,
            "ifname": i.ifname,
            "kind": i.kind,
            "enabled": i.enabled,
            "ipv4": i.ipv4,
            "vlan": i.vlan,
            "zone": zone_names.get(i.zone_fmc_id or ""),
        }
        for i in db.scalars(
            select(Interface)
            .where(Interface.snapshot_id == snapshot_id, Interface.cluster_fmc_id == cluster_id)
            .order_by(Interface.name)
        )
    ]
    routes = [
        {
            "kind": r.kind,
            "network": r.network,
            "network_name": r.network_name,
            "interface": r.interface,
            "gateway": r.gateway,
            "gateway_is_literal": r.gateway_is_literal,
            "metric": r.metric,
        }
        for r in db.scalars(
            select(Route)
            .where(Route.snapshot_id == snapshot_id, Route.cluster_fmc_id == cluster_id)
            .order_by(Route.kind, Route.network)
        )
    ]
    bgp = [
        {"as_number": b.as_number, "router_id": b.router_id, "neighbors": b.neighbors}
        for b in db.scalars(
            select(Bgp).where(Bgp.snapshot_id == snapshot_id, Bgp.cluster_fmc_id == cluster_id)
        )
    ]
    return NetworkOut(interfaces=interfaces, routes=routes, bgp=bgp)
