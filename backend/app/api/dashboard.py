"""Summary dashboard: one aggregated, read-only view of a snapshot's analysis."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.analysis.connectivity import RISK_ORDER
from app.api.scope import PolicyQuery, enforced, policy_or_shared
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.config import get_settings
from app.db.session import get_db
from app.models.assets import ClusterSetting, RuleScore
from app.models.inventory import Cluster, ClusterPolicy, Finding, FwObject, Policy, Rule, Snapshot
from app.models.map import MapEdge
from app.models.recommendations import Recommendation

router = APIRouter(prefix="/api", tags=["dashboard"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
TOP = 10
SCORE_BUCKETS = ((0, 19), (20, 39), (40, 59), (60, 79), (80, 100))


class Counted(BaseModel):
    key: str
    count: int
    extra: dict[str, Any] = {}


class ClusterUsage(BaseModel):
    id: str
    name: str
    rule_count: int
    ace_total: int | None
    ace_limit: int
    ace_limit_verified: bool


class Connection(BaseModel):
    src: str
    dst: str
    risk: str
    rule_count: int
    hits: int


class WorstRule(BaseModel):
    id: str
    name: str
    index: int
    policy_id: str
    policy_name: str
    score: int


class SnapshotStatus(BaseModel):
    id: int
    connection_name: str
    fmc_version: str | None
    created_at: datetime
    finished_at: datetime | None
    analyzed_at: datetime | None


class Dashboard(BaseModel):
    snapshot: SnapshotStatus
    totals: dict[str, int]
    findings_by_severity: dict[str, int]
    findings_by_kind: list[Counted]
    recommendations_by_kind: list[Counted]
    score_buckets: list[Counted]
    rules_by_action: list[Counted]
    clusters: list[ClusterUsage]
    map_risk: dict[str, int]
    riskiest_connections: list[Connection]
    worst_rules: list[WorstRule]


@router.get("/snapshots/{snapshot_id}/dashboard", response_model=Dashboard)
def dashboard(snapshot_id: int, db: DbDep, _: ReaderDep, policy: PolicyQuery = None) -> Dashboard:
    """The snapshot at a glance; ``policy`` narrows it to one policy (plus the shared object
    findings and recommendations, which serve every policy)."""
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    sid = snapshot_id

    def count(model: Any) -> int:
        return (
            db.scalar(select(func.count()).select_from(model).where(model.snapshot_id == sid)) or 0
        )

    rule_scope = [Rule.policy_fmc_id == policy] if policy is not None else []
    rules_in_scope = select(Rule.id).where(Rule.snapshot_id == sid, *rule_scope)
    governing = set(
        db.scalars(
            select(ClusterPolicy.cluster_fmc_id).where(
                ClusterPolicy.snapshot_id == sid, ClusterPolicy.policy_fmc_id == policy
            )
        )
    )
    severities = {"high": 0, "medium": 0, "low": 0, "info": 0}
    by_kind: dict[str, dict[str, int]] = {}
    for kind, severity, n in db.execute(
        select(Finding.kind, Finding.severity, func.count())
        .where(Finding.snapshot_id == sid, policy_or_shared(Finding.policy_fmc_id, policy))
        .group_by(Finding.kind, Finding.severity)
    ).all():
        severities[severity] = severities.get(severity, 0) + n
        by_kind.setdefault(kind, {})[severity] = n
    findings_by_kind = sorted(
        (Counted(key=k, count=sum(v.values()), extra=v) for k, v in by_kind.items()),
        key=lambda c: -c.count,
    )

    recs = [
        Counted(key=k, count=n, extra={"deploy_cost": cost or 0, "ace_delta": ace or 0})
        for k, n, cost, ace in db.execute(
            select(
                Recommendation.kind,
                func.count(),
                func.sum(Recommendation.deploy_cost),
                func.sum(Recommendation.ace_delta),
            )
            .where(
                Recommendation.snapshot_id == sid,
                policy_or_shared(Recommendation.policy_fmc_id, policy),
            )
            .group_by(Recommendation.kind)
            .order_by(func.count().desc())
        ).all()
    ]

    bucket = case(
        *((RuleScore.score.between(lo, hi), f"{lo}-{hi}") for lo, hi in SCORE_BUCKETS),
        else_="none",
    )
    buckets: dict[str, int] = dict(
        db.execute(
            select(bucket, func.count())
            .where(
                RuleScore.snapshot_id == sid,
                RuleScore.score.is_not(None),
                RuleScore.rule_id.in_(rules_in_scope),
            )
            .group_by(bucket)
        ).all()
    )
    score_buckets = [
        Counted(key=f"{lo}-{hi}", count=int(buckets.get(f"{lo}-{hi}", 0)))
        for lo, hi in SCORE_BUCKETS
    ]
    rules_by_action = [
        Counted(key=a, count=n)
        for a, n in db.execute(
            select(Rule.action, func.count())
            .where(Rule.snapshot_id == sid, Rule.policy_kind == "access", *rule_scope)
            .group_by(Rule.action)
            .order_by(func.count().desc())
        ).all()
    ]

    ace_totals = snap.stats.get("ace_by_cluster") or {}
    limits = {x.cluster_fmc_id: x for x in db.scalars(select(ClusterSetting))}
    default_limit = get_settings().default_ace_limit
    access_rules: dict[str, int] = dict(
        db.execute(
            select(ClusterPolicy.cluster_fmc_id, func.sum(Policy.rule_count))
            .join(
                Policy,
                (Policy.snapshot_id == ClusterPolicy.snapshot_id)
                & (Policy.fmc_id == ClusterPolicy.policy_fmc_id),
            )
            .where(ClusterPolicy.snapshot_id == sid, Policy.kind == "access")
            .group_by(ClusterPolicy.cluster_fmc_id)
        ).all()
    )
    clusters = [
        ClusterUsage(
            id=c.fmc_id,
            name=c.name,
            rule_count=int(access_rules.get(c.fmc_id, 0)),
            ace_total=ace_totals.get(c.fmc_id),
            ace_limit=limits[c.fmc_id].ace_limit if c.fmc_id in limits else default_limit,
            ace_limit_verified=bool(c.fmc_id in limits and limits[c.fmc_id].ace_limit_verified),
        )
        for c in db.scalars(
            select(Cluster).where(Cluster.snapshot_id == sid).order_by(Cluster.name)
        )
        if policy is None or c.fmc_id in governing
    ]

    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for src, dst, risk, rules, hits in db.execute(
        select(
            MapEdge.src_node, MapEdge.dst_node, MapEdge.risk, MapEdge.rule_count, MapEdge.hits
        ).where(
            MapEdge.snapshot_id == sid,
            MapEdge.policy_fmc_id == policy
            if policy is not None
            else MapEdge.policy_fmc_id.in_(enforced(sid)),
        )
    ).all():
        cur = pairs.setdefault((src, dst), {"risk": "green", "rules": 0, "hits": 0})
        cur["risk"] = max(cur["risk"], risk, key=RISK_ORDER.__getitem__)
        cur["rules"] += rules
        cur["hits"] += hits
    map_risk = {"red": 0, "yellow": 0, "green": 0}
    for v in pairs.values():
        map_risk[v["risk"]] += 1
    riskiest = sorted(
        pairs.items(), key=lambda kv: (-RISK_ORDER[kv[1]["risk"]], -kv[1]["rules"], kv[0])
    )[:TOP]

    policy_names = dict(
        db.execute(select(Policy.fmc_id, Policy.name).where(Policy.snapshot_id == sid)).all()
    )
    worst = db.execute(
        select(Rule.fmc_id, Rule.name, Rule.rule_index, Rule.policy_fmc_id, RuleScore.score)
        .join(RuleScore, RuleScore.rule_id == Rule.id)
        .where(Rule.snapshot_id == sid, RuleScore.score.is_not(None), *rule_scope)
        .order_by(RuleScore.score, Rule.rule_index)
        .limit(TOP)
    ).all()

    return Dashboard(
        snapshot=SnapshotStatus(
            id=snap.id,
            connection_name=snap.connection_name,
            fmc_version=snap.fmc_version,
            created_at=snap.created_at,
            finished_at=snap.finished_at,
            analyzed_at=snap.analyzed_at,
        ),
        totals={
            "rules": db.scalar(
                select(func.count()).select_from(Rule).where(Rule.snapshot_id == sid, *rule_scope)
            )
            or 0,
            "policies": 1 if policy is not None else count(Policy),
            "objects": count(FwObject),
            "clusters": len(governing) if policy is not None else count(Cluster),
            "findings": sum(severities.values()),
            "recommendations": sum(r.count for r in recs),
            "dead_rules": db.scalar(
                select(func.count()).where(
                    RuleScore.snapshot_id == sid,
                    RuleScore.dead.is_(True),
                    RuleScore.rule_id.in_(rules_in_scope),
                )
            )
            or 0,
            "shadowed_rules": db.scalar(
                select(func.count()).where(
                    RuleScore.snapshot_id == sid,
                    RuleScore.shadowed_by.is_not(None),
                    RuleScore.rule_id.in_(rules_in_scope),
                )
            )
            or 0,
        },
        findings_by_severity=severities,
        findings_by_kind=findings_by_kind,
        recommendations_by_kind=recs,
        score_buckets=score_buckets,
        rules_by_action=rules_by_action,
        clusters=clusters,
        map_risk=map_risk,
        riskiest_connections=[
            Connection(src=s, dst=d, risk=v["risk"], rule_count=v["rules"], hits=v["hits"])
            for (s, d), v in riskiest
        ],
        worst_rules=[
            WorstRule(
                id=fid,
                name=name,
                index=index,
                policy_id=policy,
                policy_name=policy_names.get(policy, policy),
                score=score or 0,
            )
            for fid, name, index, policy, score in worst
        ],
    )
