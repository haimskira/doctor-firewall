"""The clean-up roadmap of a snapshot: preparation checks and the phases in order, with what is
left in each (see app.analysis.roadmap for the order and why)."""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.roadmap import PHASES
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.config import get_settings
from app.db.session import get_db
from app.enforce.staleness import stale_since
from app.models.assets import Asset, ClusterSetting
from app.models.enforce import Changeset, ChangesetItem
from app.models.inventory import Cluster, Policy, Rule, Snapshot
from app.models.recommendations import Recommendation, RecommendationDecision, behavior

router = APIRouter(prefix="/api", tags=["roadmap"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]


class Counts(BaseModel):
    total: int = 0
    open: int = 0
    accepted: int = 0  # accepted, not yet in an open changeset
    staged: int = 0  # in an open changeset
    dismissed: int = 0
    ace_delta: int = 0


class PhaseKind(Counts):
    kind: str


class PhaseOut(Counts):
    name: str
    status: Literal["done", "current", "next"]
    behavior: Literal["preserves", "changes"]
    kinds: list[PhaseKind]


class Check(BaseModel):
    code: str
    ok: bool
    args: dict[str, Any] = {}


class RoadmapOut(BaseModel):
    snapshot_id: int
    prepare: list[Check]
    phases: list[PhaseOut]
    current: str | None


def _checks(db: Session, snap: Snapshot) -> list[Check]:
    sid = snap.id
    assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.confirmed.is_(True)))
    clusters = list(db.scalars(select(Cluster.fmc_id).where(Cluster.snapshot_id == sid)))
    verified = set(
        db.scalars(
            select(ClusterSetting.cluster_fmc_id).where(
                ClusterSetting.cluster_fmc_id.in_(clusters),
                ClusterSetting.ace_limit_verified.is_(True),
                ClusterSetting.deploy_limit_verified.is_(True),
            )
        )
    )
    rules, with_hits = db.execute(
        select(func.count(), func.count(Rule.hit_count))
        .join(
            Policy, (Policy.snapshot_id == Rule.snapshot_id) & (Policy.fmc_id == Rule.policy_fmc_id)
        )
        .where(Rule.snapshot_id == sid, Policy.kind == "access", Rule.enabled.is_(True))
    ).one()
    stale = stale_since(db, snap)
    return [
        Check(code="assets", ok=(assets or 0) > 0, args={"count": assets or 0}),
        Check(
            code="limits",
            ok=bool(clusters) and len(verified) == len(clusters),
            args={"unverified": len(set(clusters) - verified), "clusters": len(clusters)},
        ),
        Check(
            code="hits",
            ok=rules > 0 and with_hits == rules,
            args={"with_hits": with_hits, "rules": rules, "days": get_settings().dead_rule_days},
        ),
        Check(
            code="fresh",
            ok=stale is None,
            args={} if stale is None else {"changeset": stale["changeset_id"]},
        ),
    ]


@router.get("/snapshots/{snapshot_id}/roadmap", response_model=RoadmapOut)
def roadmap(snapshot_id: int, db: DbDep, _: ReaderDep) -> RoadmapOut:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    staged = set(
        db.scalars(
            select(ChangesetItem.fingerprint)
            .join(Changeset, Changeset.id == ChangesetItem.changeset_id)
            .where(Changeset.status.in_(("open", "in_progress")))
        )
    )
    by_kind: dict[str, Counts] = defaultdict(Counts)
    for kind, fingerprint, ace, decision in db.execute(
        select(
            Recommendation.kind,
            Recommendation.fingerprint,
            Recommendation.ace_delta,
            RecommendationDecision.status,
        )
        .outerjoin(
            RecommendationDecision,
            RecommendationDecision.fingerprint == Recommendation.fingerprint,
        )
        .where(Recommendation.snapshot_id == snapshot_id)
    ):
        c = by_kind[kind]
        c.total += 1
        c.ace_delta += ace
        if fingerprint in staged:
            c.staged += 1
        elif decision == "accepted":
            c.accepted += 1
        elif decision == "dismissed":
            c.dismissed += 1
        else:
            c.open += 1
    phases: list[PhaseOut] = []
    current: str | None = None
    for name, kinds in PHASES:
        rows = [PhaseKind(kind=k, **by_kind[k].model_dump()) for k in kinds if k in by_kind]
        totals = Counts(
            **{
                f: sum(getattr(r, f) for r in rows)
                for f in ("total", "open", "accepted", "staged", "dismissed", "ace_delta")
            }
        )
        # Done: nothing left to decide or to stage (staged items wait for their deployment).
        done = totals.open == 0 and totals.accepted == 0
        state: Literal["done", "current", "next"] = "done"
        if not done:
            state = "current" if current is None else "next"
            current = current or name
        phases.append(
            PhaseOut(
                name=name,
                status=state,
                behavior="changes" if any(behavior(k) == "changes" for k in kinds) else "preserves",
                kinds=rows,
                **totals.model_dump(),
            )
        )
    return RoadmapOut(
        snapshot_id=snapshot_id, prepare=_checks(db, snap), phases=phases, current=current
    )
