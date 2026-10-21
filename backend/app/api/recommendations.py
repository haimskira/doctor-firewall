"""Phase 3: recommendations, operator decisions and the naming convention.

Everything here acts on the local copy only. A decision (accept / dismiss) is a local,
audited record; accepted recommendations become changeset input in phase 5 — no
endpoint in this module talks to the FMC.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.analysis.naming import TOKENS_BY_KIND, TemplateError, validate_template
from app.api.schemas import StrictModel
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.inventory import Snapshot
from app.models.recommendations import (
    CONVENTION_KINDS,
    RECOMMENDATION_KINDS,
    NamingConvention,
    Recommendation,
    RecommendationDecision,
)
from app.runtime import get_audit
from app.workers import jobs

router = APIRouter(prefix="/api", tags=["recommendations"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
OptimizerDep = Annotated[Principal, Depends(require(Permission.CHANGESET_WRITE))]
ConventionDep = Annotated[Principal, Depends(require(Permission.CONVENTIONS_MANAGE))]
CollectorDep = Annotated[Principal, Depends(require(Permission.COLLECT_RUN))]
FmcIdQuery = Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
KindPattern = "^(" + "|".join(RECOMMENDATION_KINDS) + ")$"
ConventionKindPath = Annotated[str, Path(pattern="^(" + "|".join(CONVENTION_KINDS) + ")$")]


# ------------------------------------------------------------------ schemas


class Decision(BaseModel):
    status: str
    note: str
    decided_by: str
    decided_at: datetime


class RecommendationOut(BaseModel):
    id: int
    kind: str
    policy_fmc_id: str | None
    title: str
    principle: str
    priority: int
    targets: list[dict[str, Any]]
    display: str
    deploy_cost: int
    ace_delta: int
    score_delta: int | None
    warnings: list[str]
    fingerprint: str
    decision: Decision | None
    # Whether the writer can apply it (phase 5) and, if not, why.
    executable: bool
    blocked: list[str]


class RecommendationDetail(RecommendationOut):
    preview: dict[str, Any]
    plan: dict[str, Any]


class KindSummary(BaseModel):
    count: int
    deploy_cost: int
    ace_delta: int


class RecommendationsPage(BaseModel):
    total: int
    offset: int
    summary: dict[str, KindSummary]
    accepted: KindSummary
    rows: list[RecommendationOut]


class DecisionIn(StrictModel):
    status: Literal["accepted", "dismissed", "open"]
    note: Annotated[str, Field(max_length=512)] = ""


class ConventionOut(BaseModel):
    kind: str
    template: str
    letter_case: str
    enabled: bool
    updated_by: str
    updated_at: datetime


class ConventionIn(StrictModel):
    template: Annotated[str, Field(min_length=1, max_length=128)]
    letter_case: Literal["upper", "lower", "keep"] = "upper"
    enabled: bool = True


class ConventionCatalog(BaseModel):
    kinds: dict[str, list[str]]
    conventions: list[ConventionOut]


# ------------------------------------------------------------------ helpers


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


def _snapshot(db: Session, snapshot_id: int) -> Snapshot:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return snap


def _decision(d: RecommendationDecision | None) -> Decision | None:
    if d is None:
        return None
    return Decision(status=d.status, note=d.note, decided_by=d.decided_by, decided_at=d.decided_at)


def _out(r: Recommendation, d: RecommendationDecision | None) -> RecommendationOut:
    return RecommendationOut(
        id=r.id,
        kind=r.kind,
        policy_fmc_id=r.policy_fmc_id,
        title=r.title,
        principle=r.principle,
        priority=r.priority,
        targets=r.targets,
        display=r.display,
        deploy_cost=r.deploy_cost,
        ace_delta=r.ace_delta,
        score_delta=r.score_delta,
        warnings=r.warnings,
        fingerprint=r.fingerprint,
        decision=_decision(d),
        executable=bool(r.plan.get("executable")),
        blocked=[str(x) for x in r.plan.get("blocked", [])],
    )


def _filtered(
    snapshot_id: int,
    kind: str | None,
    policy: str | None,
    state: str | None,
    q: str | None,
    rule: str | None,
) -> Select[Recommendation, RecommendationDecision]:
    query = (
        select(Recommendation, RecommendationDecision)
        .outerjoin(
            RecommendationDecision,
            RecommendationDecision.fingerprint == Recommendation.fingerprint,
        )
        .where(Recommendation.snapshot_id == snapshot_id)
    )
    if kind:
        query = query.where(Recommendation.kind == kind)
    if policy:
        query = query.where(Recommendation.policy_fmc_id == policy)
    if state == "open":
        query = query.where(RecommendationDecision.fingerprint.is_(None))
    elif state in ("accepted", "dismissed"):
        query = query.where(RecommendationDecision.status == state)
    if q:
        query = query.where(func.lower(Recommendation.title).contains(q.lower(), autoescape=True))
    if rule:
        query = query.where(Recommendation.targets.contains([{"type": "rule", "id": rule}]))
    return query


# ------------------------------------------------------------------ recommendations


@router.get("/snapshots/{snapshot_id}/recommendations", response_model=RecommendationsPage)
def list_recommendations(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    kind: Annotated[str | None, Query(pattern=KindPattern)] = None,
    policy: FmcIdQuery = None,
    state: Annotated[str | None, Query(pattern="^(open|accepted|dismissed)$")] = None,
    rule: FmcIdQuery = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
    offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> RecommendationsPage:
    """The recommendation queue: highest priority first, with impact and deploy cost."""
    _snapshot(db, snapshot_id)
    query = _filtered(snapshot_id, kind, policy, state, q, rule)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(
        query.order_by(Recommendation.priority.desc(), Recommendation.kind, Recommendation.id)
        .offset(offset)
        .limit(limit)
    ).all()
    summary = {
        k: KindSummary(count=c, deploy_cost=cost or 0, ace_delta=ace or 0)
        for k, c, cost, ace in db.execute(
            select(
                Recommendation.kind,
                func.count(),
                func.sum(Recommendation.deploy_cost),
                func.sum(Recommendation.ace_delta),
            )
            .where(Recommendation.snapshot_id == snapshot_id)
            .group_by(Recommendation.kind)
        ).all()
    }
    accepted = db.execute(
        select(
            func.count(),
            func.coalesce(func.sum(Recommendation.deploy_cost), 0),
            func.coalesce(func.sum(Recommendation.ace_delta), 0),
        )
        .join(
            RecommendationDecision,
            RecommendationDecision.fingerprint == Recommendation.fingerprint,
        )
        .where(
            Recommendation.snapshot_id == snapshot_id,
            RecommendationDecision.status == "accepted",
        )
    ).one()
    return RecommendationsPage(
        total=total,
        offset=offset,
        summary=summary,
        accepted=KindSummary(count=accepted[0], deploy_cost=accepted[1], ace_delta=accepted[2]),
        rows=[_out(r, d) for r, d in rows],
    )


@router.get(
    "/snapshots/{snapshot_id}/recommendations/{rec_id}", response_model=RecommendationDetail
)
def get_recommendation(
    snapshot_id: int, rec_id: int, db: DbDep, _: ReaderDep
) -> RecommendationDetail:
    row = db.execute(
        select(Recommendation, RecommendationDecision)
        .outerjoin(
            RecommendationDecision,
            RecommendationDecision.fingerprint == Recommendation.fingerprint,
        )
        .where(Recommendation.snapshot_id == snapshot_id, Recommendation.id == rec_id)
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    rec, decision = row
    return RecommendationDetail(
        **_out(rec, decision).model_dump(), preview=rec.preview, plan=rec.plan
    )


@router.put(
    "/snapshots/{snapshot_id}/recommendations/{rec_id}/decision",
    response_model=RecommendationOut,
)
def decide(
    snapshot_id: int,
    rec_id: int,
    body: DecisionIn,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    who: OptimizerDep,
) -> RecommendationOut:
    """Accept or dismiss a recommendation (local only), or reopen it."""
    rec = db.scalar(
        select(Recommendation).where(
            Recommendation.snapshot_id == snapshot_id, Recommendation.id == rec_id
        )
    )
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    current = db.get(RecommendationDecision, rec.fingerprint, with_for_update=True)
    if body.status == "open":
        if current is not None:
            db.delete(current)
        current = None
    elif current is None:
        current = RecommendationDecision(
            fingerprint=rec.fingerprint,
            status=body.status,
            note=body.note,
            decided_by=who.username,
        )
        db.add(current)
    else:
        current.status = body.status
        current.note = body.note
        current.decided_by = who.username
    _audit(
        audit,
        db,
        who,
        request,
        f"recommendation.{body.status}",
        rec.title[:256],
        {"snapshot_id": snapshot_id, "kind": rec.kind, "fingerprint": rec.fingerprint},
    )
    db.commit()
    if current is not None:
        db.refresh(current)
    return _out(rec, current)


@router.post(
    "/snapshots/{snapshot_id}/analyze",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=dict[str, int],
)
def reanalyze(
    snapshot_id: int, request: Request, db: DbDep, audit: AuditDep, who: CollectorDep
) -> dict[str, int]:
    """Re-run analysis and recommendations (e.g. after asset-table or convention changes)."""
    snap = _snapshot(db, snapshot_id)
    if snap.status != "complete":
        raise HTTPException(status.HTTP_409_CONFLICT, "snapshot_not_complete")
    _audit(
        audit, db, who, request, "analysis.request", snap.connection_name, {"snapshot_id": snap.id}
    )
    db.commit()
    jobs.enqueue_analysis(snap.id)
    return {"snapshot_id": snap.id}


# ------------------------------------------------------------------ naming convention


def _convention_out(c: NamingConvention) -> ConventionOut:
    return ConventionOut(
        kind=c.kind,
        template=c.template,
        letter_case=c.letter_case,
        enabled=c.enabled,
        updated_by=c.updated_by,
        updated_at=c.updated_at,
    )


@router.get("/naming-conventions", response_model=ConventionCatalog)
def list_conventions(db: DbDep, _: ReaderDep) -> ConventionCatalog:
    return ConventionCatalog(
        kinds={k: sorted(v) for k, v in TOKENS_BY_KIND.items()},
        conventions=[
            _convention_out(c)
            for c in db.scalars(select(NamingConvention).order_by(NamingConvention.kind))
        ],
    )


@router.put("/naming-conventions/{kind}", response_model=ConventionOut)
def set_convention(
    kind: ConventionKindPath,
    body: ConventionIn,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    who: ConventionDep,
) -> ConventionOut:
    try:
        validate_template(kind, body.template)
    except TemplateError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    current = db.get(NamingConvention, kind, with_for_update=True)
    if current is None:
        current = NamingConvention(kind=kind, updated_by=who.username, **body.model_dump())
        db.add(current)
    else:
        current.template = body.template
        current.letter_case = body.letter_case
        current.enabled = body.enabled
        current.updated_by = who.username
    _audit(audit, db, who, request, "naming.set", kind, body.model_dump())
    db.commit()
    db.refresh(current)
    return _convention_out(current)


@router.delete("/naming-conventions/{kind}", status_code=status.HTTP_204_NO_CONTENT)
def delete_convention(
    kind: ConventionKindPath, request: Request, db: DbDep, audit: AuditDep, who: ConventionDep
) -> None:
    current = db.get(NamingConvention, kind)
    if current is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    db.delete(current)
    _audit(audit, db, who, request, "naming.delete", kind, {})
    db.commit()
