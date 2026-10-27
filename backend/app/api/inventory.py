"""Snapshots and the collected inventory (read-only views + collection triggers)."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import Select, case, func, literal, or_, select
from sqlalchemy.orm import Session

from app.analysis import routing
from app.analysis.expand import ACE_FIELDS
from app.api.sorting import SortColumns, SortOrder, order_by
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
from app.models.assets import ClusterSetting, RuleScore
from app.models.fmc import FmcConnection
from app.models.inventory import (
    Bgp,
    Cluster,
    ClusterPolicy,
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
from app.models.recommendations import Recommendation, RecommendationDecision
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


class GoverningPolicy(BaseModel):
    id: str
    name: str
    kind: str
    via: str
    rule_count: int


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
    policies: list[GoverningPolicy]
    ace_total: int | None
    ace_limit: int
    ace_limit_verified: bool


class ScoredRule(BaseModel):
    policy_fmc_id: str
    policy_name: str
    rule_id: str
    rule_index: int
    rule_name: str
    action: str
    score: int
    ace_count: int
    reasons: list[dict[str, Any]]
    dst_tiers: list[str]


class PolicyOut(BaseModel):
    id: str
    kind: str
    name: str
    default_action: str
    rule_count: int
    links: list[dict[str, str]]
    attrs: dict[str, Any]
    clusters: list[str]


class RefOut(BaseModel):
    id: str | None = None
    name: str = ""
    kind: str | None = None
    literal: str | None = None


class RuleOut(BaseModel):
    id: str
    rule_type: str | None
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
    score: int | None = None
    ace_count: int | None = None
    reasons: list[dict[str, Any]] = []
    src_tiers: list[str] = []
    dst_tiers: list[str] = []
    shadowed_by: str | None = None
    dead: bool = False
    # Open (undecided or accepted) recommendations touching this rule: the editor's tags.
    recommendations: list[RuleRecTag] = []


class RuleRecTag(BaseModel):
    id: int
    kind: str
    deploy_cost: int
    status: str  # open | accepted


class RuleGroup(BaseModel):
    """A contiguous run of rules with the same section and category (FMC section rows)."""

    section: str
    category: str
    start: int  # 0-based position in the (filtered) ordered rule list
    count: int
    first_index: int
    last_index: int


class RulesPage(BaseModel):
    policy_fmc_id: str
    policy_kind: str
    policy_name: str
    default_action: str
    groups: list[RuleGroup]
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
    policy_kind: str
    policy_name: str
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
    # Recommendations of the same snapshot that act on what the finding is about.
    fixes: list[dict[str, Any]] = []


def _finding_targets(details: dict[str, Any]) -> list[str]:
    """FMC ids a finding is about: its rule(s) and object(s)."""
    out: list[str] = []

    def take(value: Any) -> None:
        if isinstance(value, dict) and isinstance(value.get("id"), str):
            out.append(value["id"])

    for key in ("rule", "object", "group"):
        take(details.get(key))
    for key in ("rules", "objects", "groups"):
        for item in details.get(key) or []:
            take(item)
    return out


MAX_NESTING = 16


def _rule_objects(db: Session, snapshot_id: int, rule_ids: set[str]) -> dict[str, list[str]]:
    """Rule FMC id -> every object it references in an ACE field, directly or nested."""
    direct: dict[str, set[str]] = defaultdict(set)
    for fmc_id, oid in db.execute(
        select(Rule.fmc_id, RuleRef.object_fmc_id)
        .join(Rule, Rule.id == RuleRef.rule_id)
        .where(
            RuleRef.snapshot_id == snapshot_id,
            Rule.fmc_id.in_(rule_ids),
            RuleRef.object_fmc_id.is_not(None),
            RuleRef.field.in_(ACE_FIELDS),
        )
    ):
        if oid is not None:
            direct[fmc_id].add(oid)
    children: dict[str, set[str]] = defaultdict(set)
    frontier = set().union(*direct.values()) if direct else set()
    seen = set(frontier)
    for _ in range(MAX_NESTING):
        if not frontier:
            break
        nxt: set[str] = set()
        for group, member in db.execute(
            select(GroupMember.group_fmc_id, GroupMember.member_fmc_id).where(
                GroupMember.snapshot_id == snapshot_id,
                GroupMember.group_fmc_id.in_(frontier),
                GroupMember.member_fmc_id.is_not(None),
            )
        ):
            if member is not None:
                children[group].add(member)
                if member not in seen:
                    seen.add(member)
                    nxt.add(member)
        frontier = nxt
    out: dict[str, list[str]] = {}
    for rule, objects in direct.items():
        found, queue = set(objects), list(objects)
        while queue:
            for child in children.get(queue.pop(), set()):
                if child not in found:
                    found.add(child)
                    queue.append(child)
        out[rule] = sorted(found)
    return out


def _fixes(
    db: Session, snapshot_id: int, findings: list[Finding]
) -> dict[int, list[dict[str, Any]]]:
    targets = {f.id: _finding_targets(f.details) for f in findings}
    # An ACE-heavy rule is fixed through the groups it uses (compacting them).
    heavy = {f.id: t[0] for f in findings if f.kind == "ace_heavy_rule" and (t := targets[f.id])}
    if heavy:
        groups = _rule_objects(db, snapshot_id, set(heavy.values()))
        for fid, rule in heavy.items():
            targets[fid] = [*targets[fid], *groups.get(rule, [])]
    wanted = {t for ts in targets.values() for t in ts}
    if not wanted:
        return {}
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec_id, kind, title, rec_targets in db.execute(
        select(Recommendation.id, Recommendation.kind, Recommendation.title, Recommendation.targets)
        .where(Recommendation.snapshot_id == snapshot_id)
        .order_by(Recommendation.priority.desc(), Recommendation.id)
    ):
        for t in rec_targets:
            tid = t.get("id") if isinstance(t, dict) else None
            if tid in wanted and len(by_target[tid]) < 5:
                by_target[tid].append({"id": rec_id, "kind": kind, "title": title[:160]})
    out: dict[int, list[dict[str, Any]]] = {}
    for f in findings:
        seen: set[int] = set()
        fixes: list[dict[str, Any]] = []
        for tid in targets[f.id]:
            for fix in by_target.get(tid, []):
                if fix["id"] not in seen:
                    seen.add(fix["id"])
                    fixes.append(fix)
        out[f.id] = fixes[:5]
    return out


class FindingsPage(BaseModel):
    total: int
    offset: int
    summary: dict[str, dict[str, int]]
    rows: list[FindingOut]


class NetworkOut(BaseModel):
    interfaces: list[dict[str, Any]]
    routes: list[dict[str, Any]]
    bgp: list[dict[str, Any]]
    # Runtime routing table of this cluster: status (ok / unsupported / unavailable / mismatch /
    # disabled), number of dynamic routes, device asked; None for snapshots before B-001.
    runtime: dict[str, Any] | None = None


class RouteMatch(BaseModel):
    kind: str
    protocol: str
    network: str
    interface: str
    zone: str | None
    gateway: str | None
    distance: int


class RouteLookupOut(BaseModel):
    ip: str
    best: RouteMatch | None
    matches: list[RouteMatch]
    runtime_status: str | None  # without "ok" dynamic routes are not part of the answer


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
    jobs.enqueue_collection(snap.id, who.username)
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
    jobs.enqueue_collection(snap.id, who.username)
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
    policies = {
        p.fmc_id: p for p in db.scalars(select(Policy).where(Policy.snapshot_id == snapshot_id))
    }
    governing: dict[str, list[GoverningPolicy]] = defaultdict(list)
    for link in db.scalars(
        select(ClusterPolicy)
        .where(ClusterPolicy.snapshot_id == snapshot_id)
        .order_by(ClusterPolicy.id)
    ):
        p = policies.get(link.policy_fmc_id)
        governing[link.cluster_fmc_id].append(
            GoverningPolicy(
                id=link.policy_fmc_id,
                name=p.name if p else link.policy_fmc_id,
                kind=p.kind if p else "unknown",
                via=link.via,
                rule_count=p.rule_count if p else 0,
            )
        )
    snapshot = db.get(Snapshot, snapshot_id)
    ace_totals = (snapshot.stats.get("ace_by_cluster") if snapshot else None) or {}
    limits = {x.cluster_fmc_id: x for x in db.scalars(select(ClusterSetting))}
    default_limit = get_settings().default_ace_limit
    result = []
    for c in db.scalars(
        select(Cluster).where(Cluster.snapshot_id == snapshot_id).order_by(Cluster.name)
    ):
        access = policies.get(c.policy_fmc_id or "")
        result.append(
            ClusterOut(
                fmc_id=c.fmc_id,
                name=c.name,
                kind=c.kind,
                sw_version=c.sw_version,
                model=c.model,
                members=c.members,
                policy_fmc_id=c.policy_fmc_id,
                policy_name=access.name if access else None,
                rule_count=access.rule_count if access else 0,
                policies=sorted(
                    governing[c.fmc_id], key=lambda g: (g.kind != "access", g.kind, g.name)
                ),
                ace_total=ace_totals.get(c.fmc_id),
                ace_limit=limits[c.fmc_id].ace_limit if c.fmc_id in limits else default_limit,
                ace_limit_verified=bool(c.fmc_id in limits and limits[c.fmc_id].ace_limit_verified),
            )
        )
    return result


@router.get("/snapshots/{snapshot_id}/scores", response_model=list[ScoredRule])
def worst_rules(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    policy_id: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    sort: Annotated[Literal["score", "ace", "index", "name", "policy"] | None, Query()] = None,
    order: SortOrder = None,
) -> list[ScoredRule]:
    """The optimisation queue: lowest-scoring permit rules first, with their reasons."""
    _snapshot(db, snapshot_id)
    query = (
        select(RuleScore, Rule, Policy.name)
        .join(Rule, Rule.id == RuleScore.rule_id)
        .join(
            Policy, (Policy.snapshot_id == Rule.snapshot_id) & (Policy.fmc_id == Rule.policy_fmc_id)
        )
        .where(RuleScore.snapshot_id == snapshot_id, RuleScore.score.is_not(None))
    )
    if policy_id:
        query = query.where(Rule.policy_fmc_id == policy_id)
    columns: SortColumns = {
        "score": RuleScore.score,
        "ace": RuleScore.ace_count,
        "index": Rule.rule_index,
        "name": Rule.name,
        "policy": Policy.name,
    }
    terms = order_by(sort, order, columns, [RuleScore.score, Rule.rule_index, Rule.id])
    rows = db.execute(query.order_by(*terms).limit(limit)).all()
    return [
        ScoredRule(
            policy_fmc_id=rule.policy_fmc_id,
            policy_name=pname,
            rule_id=rule.fmc_id,
            rule_index=rule.rule_index,
            rule_name=rule.name,
            action=rule.action,
            score=sc.score or 0,
            ace_count=sc.ace_count,
            reasons=sc.reasons,
            dst_tiers=sc.dst_tiers,
        )
        for sc, rule, pname in rows
    ]


@router.get("/snapshots/{snapshot_id}/policies", response_model=list[PolicyOut])
def list_policies(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    kind: Annotated[str | None, Query(pattern=r"^[a-z]{1,16}$")] = None,
) -> list[PolicyOut]:
    """Inventory of every collected policy and the clusters it governs."""
    _snapshot(db, snapshot_id)
    names = dict(
        db.execute(
            select(Cluster.fmc_id, Cluster.name).where(Cluster.snapshot_id == snapshot_id)
        ).all()
    )
    governs: dict[str, list[str]] = defaultdict(list)
    for link in db.scalars(select(ClusterPolicy).where(ClusterPolicy.snapshot_id == snapshot_id)):
        governs[link.policy_fmc_id].append(names.get(link.cluster_fmc_id, link.cluster_fmc_id))
    query = select(Policy).where(Policy.snapshot_id == snapshot_id)
    if kind:
        query = query.where(Policy.kind == kind)
    return [
        PolicyOut(
            id=p.fmc_id,
            kind=p.kind,
            name=p.name,
            default_action=p.default_action,
            rule_count=p.rule_count,
            links=p.links,
            attrs=p.attrs,
            clusters=sorted(governs[p.fmc_id]),
        )
        for p in db.scalars(query.order_by(Policy.kind, Policy.name))
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
    # Section runs are only needed once per query (the client keeps them across pages).
    groups = _rule_groups(db, base) if offset == 0 else []
    # NAT is evaluated manual (before auto) -> auto -> manual (after auto).
    section_rank = case(
        (Rule.section == "BEFORE_AUTO", 0),
        (Rule.section == "AUTO", 1),
        (Rule.section == "AFTER_AUTO", 2),
        else_=0,
    )
    rules = list(
        db.scalars(base.order_by(section_rank, Rule.rule_index).offset(offset).limit(limit))
    )
    refs: dict[int, dict[str, list[RefOut]]] = defaultdict(lambda: defaultdict(list))
    scores = (
        {
            sc.rule_id: sc
            for sc in db.scalars(
                select(RuleScore).where(RuleScore.rule_id.in_([r.id for r in rules]))
            )
        }
        if rules
        else {}
    )
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
    tags = _recommendation_tags(db, snapshot_id, policy.fmc_id, {r.fmc_id for r in rules})
    return RulesPage(
        policy_fmc_id=policy.fmc_id,
        policy_kind=policy.kind,
        policy_name=policy.name,
        default_action=policy.default_action,
        groups=groups,
        categories=policy.categories,
        total=total,
        offset=offset,
        rows=[
            RuleOut(
                id=r.fmc_id,
                rule_type=r.rule_type,
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
                recommendations=tags.get(r.fmc_id, []),
                **_score_fields(scores.get(r.id)),
            )
            for r in rules
        ],
    )


def _recommendation_tags(
    db: Session, snapshot_id: int, policy_id: str, rule_ids: set[str]
) -> dict[str, list[RuleRecTag]]:
    """Recommendations (not dismissed) per rule of this page."""
    if not rule_ids:
        return {}
    tags: dict[str, list[RuleRecTag]] = defaultdict(list)
    for rec_id, kind, cost, targets, decision in db.execute(
        select(
            Recommendation.id,
            Recommendation.kind,
            Recommendation.deploy_cost,
            Recommendation.targets,
            RecommendationDecision.status,
        )
        .outerjoin(
            RecommendationDecision,
            RecommendationDecision.fingerprint == Recommendation.fingerprint,
        )
        .where(
            Recommendation.snapshot_id == snapshot_id,
            Recommendation.policy_fmc_id == policy_id,
            or_(
                RecommendationDecision.status.is_(None),
                RecommendationDecision.status != "dismissed",
            ),
        )
        .order_by(Recommendation.priority.desc(), Recommendation.id)
    ).all():
        for target in targets:
            rid = target.get("id")
            if target.get("type") == "rule" and rid in rule_ids:
                tags[rid].append(
                    RuleRecTag(id=rec_id, kind=kind, deploy_cost=cost, status=decision or "open")
                )
    return tags


def _rule_groups(db: Session, base: Select[Any]) -> list[RuleGroup]:
    """Contiguous (section, category) runs over the ordered (and filtered) rules."""
    ordered = base.with_only_columns(Rule.section, Rule.category, Rule.rule_index).order_by(
        case(
            (Rule.section == "BEFORE_AUTO", 0),
            (Rule.section == "AUTO", 1),
            (Rule.section == "AFTER_AUTO", 2),
            else_=0,
        ),
        Rule.rule_index,
    )
    groups: list[RuleGroup] = []
    for position, (section, category, index) in enumerate(db.execute(ordered).all()):
        last = groups[-1] if groups else None
        if last is not None and last.section == section and last.category == category:
            last.count += 1
            last.last_index = index
        else:
            groups.append(
                RuleGroup(
                    section=section,
                    category=category,
                    start=position,
                    count=1,
                    first_index=index,
                    last_index=index,
                )
            )
    return groups


def _score_fields(sc: RuleScore | None) -> dict[str, Any]:
    if sc is None:
        return {}
    return {
        "score": sc.score,
        "ace_count": sc.ace_count,
        "reasons": sc.reasons,
        "src_tiers": sc.src_tiers,
        "dst_tiers": sc.dst_tiers,
        "shadowed_by": sc.shadowed_by,
        "dead": sc.dead,
    }


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
    sort: Annotated[
        Literal["name", "kind", "value", "rule_refs", "member_of"] | None, Query()
    ] = None,
    order: SortOrder = None,
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
    columns: SortColumns = {
        "name": FwObject.name,
        "kind": FwObject.kind,
        "value": FwObject.value,
        "rule_refs": query.selected_columns["rule_refs"],
        "member_of": query.selected_columns["member_of"],
    }
    terms = order_by(sort, order, columns, [FwObject.name, FwObject.fmc_id])
    rows = db.execute(query.order_by(*terms).offset(offset).limit(limit))
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
            Rule.policy_kind,
            Policy.name,
            Rule.fmc_id,
            Rule.rule_index,
            Rule.name,
            RuleRef.field,
            RuleRef.object_fmc_id,
        )
        .join(RuleRef, RuleRef.rule_id == Rule.id)
        .join(
            Policy, (Policy.snapshot_id == Rule.snapshot_id) & (Policy.fmc_id == Rule.policy_fmc_id)
        )
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id.in_(via_ids))
    )
    total = db.scalar(select(func.count()).select_from(usage_query.subquery())) or 0
    used_by = [
        UsageOut(
            policy_fmc_id=p,
            policy_kind=pkind,
            policy_name=pname,
            rule_id=rid,
            rule_index=idx,
            rule_name=rname,
            field=fld,
            via_id=via or "",
            via_name=names.get(via or "", ""),
        )
        for p, pkind, pname, rid, idx, rname, fld, via in db.execute(
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
    sort: Annotated[Literal["severity", "kind", "title"] | None, Query()] = None,
    order: SortOrder = None,
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
    # "high" first is rank 1: a descending severity sort puts the highest first.
    severity_rank = func.array_position(
        literal(["info", "low", "medium", "high"]), Finding.severity
    )
    columns: SortColumns = {
        "severity": severity_rank,
        "kind": Finding.kind,
        "title": Finding.title,
    }
    terms = order_by(sort, order, columns, [severity_order, Finding.kind, Finding.id])
    found = list(db.scalars(query.order_by(*terms).offset(offset).limit(limit)))
    fixes = _fixes(db, snapshot_id, found)
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
                fixes=fixes.get(f.id, []),
            )
            for f in found
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
            "protocol": r.protocol,
            "distance": r.distance,
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
    return NetworkOut(
        interfaces=interfaces,
        routes=routes,
        bgp=bgp,
        runtime=_runtime_status(db, snapshot_id, cluster_id),
    )


def _runtime_status(db: Session, snapshot_id: int, cluster_id: str) -> dict[str, Any] | None:
    snap = db.get(Snapshot, snapshot_id)
    runtime = (snap.stats or {}).get("runtime_routes") if snap is not None else None
    value = runtime.get(cluster_id) if isinstance(runtime, dict) else None
    return value if isinstance(value, dict) else None


@router.get(
    "/snapshots/{snapshot_id}/clusters/{cluster_id}/route-lookup", response_model=RouteLookupOut
)
def route_lookup(
    snapshot_id: int,
    cluster_id: FmcIdPath,
    ip: Annotated[str, Query(min_length=7, max_length=15, pattern=r"^[0-9.]+$")],
    db: DbDep,
    _: ReaderDep,
) -> RouteLookupOut:
    """Route, interface and zone the cluster uses for an IPv4 address (longest prefix)."""
    try:
        address = str(ipaddress.IPv4Address(ip))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_ip") from exc
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
    zones: dict[str, str | None] = {}
    for name, ifname, zone_id in db.execute(
        select(Interface.name, Interface.ifname, Interface.zone_fmc_id).where(
            Interface.snapshot_id == snapshot_id, Interface.cluster_fmc_id == cluster_id
        )
    ).all():
        for key in (name, ifname):
            if key:
                zones[key] = zone_names.get(zone_id or "")
    candidates = [
        routing.Candidate(
            kind=r.kind,
            protocol=r.protocol or r.kind,
            network=r.network,
            interface=r.interface,
            gateway=r.gateway,
            distance=routing.distance_of(r.kind, r.metric, r.distance),
        )
        for r in db.scalars(
            select(Route).where(
                Route.snapshot_id == snapshot_id,
                Route.cluster_fmc_id == cluster_id,
                Route.network.is_not(None),
            )
        )
        if r.network is not None and ":" not in r.network
    ]
    matches = [
        RouteMatch(
            kind=c.kind,
            protocol=c.protocol,
            network=c.network,
            interface=c.interface,
            zone=zones.get(c.interface),
            gateway=c.gateway,
            distance=c.distance,
        )
        for c in routing.lookup(address, candidates)
    ]
    runtime = _runtime_status(db, snapshot_id, cluster_id)
    return RouteLookupOut(
        ip=address,
        best=matches[0] if matches else None,
        matches=matches[:20],
        runtime_status=str(runtime.get("status")) if runtime else None,
    )
