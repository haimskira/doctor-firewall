"""System dossier (read-only): one asset-table system, who reaches it and what it reaches."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.assets import effective_assets
from app.analysis.dossier import build_dossier
from app.api.attack import ClusterQuery, _hops, _snapshot
from app.api.scope import PolicyQuery, ensure_scoped
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.assets import AssetGroup

router = APIRouter(prefix="/api", tags=["dossier"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
SystemQuery = Annotated[str, Query(min_length=3, max_length=200)]


class DossierSystem(BaseModel):
    id: str  # TIER|name, as on the connectivity map and the attack surface
    name: str
    tier: str
    kind: str  # system / server / user / user_segment / entry (stand-alone row)
    owner: str
    description: str
    components: list[dict[str, Any]]


class Dossier(BaseModel):
    system: DossierSystem
    inbound: list[dict[str, Any]]
    outbound: list[dict[str, Any]]
    summary: dict[str, Any]


@router.get("/snapshots/{snapshot_id}/dossier", response_model=Dossier)
def system_dossier(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    system: SystemQuery,
    cluster: ClusterQuery = None,
    policy: PolicyQuery = None,
) -> Dossier:
    """Who reaches the system (``inbound``) and what it reaches (``outbound``), per peer with
    services as ``TCP-443`` and the rules that allow it; derived from the snapshot's rulebase.

    ``system`` is ``TIER|name`` of the confirmed asset table. With ``policy`` only that policy's
    rules count (its world); otherwise every policy some device enforces.
    """
    snap = _snapshot(db, snapshot_id)
    tier, sep, name = system.partition("|")
    rows = effective_assets(db)
    if not sep or not any(r.system == name and r.tier == tier for r in rows):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_target")
    if policy is not None:
        ensure_scoped(db, snapshot_id, policy)
    result = build_dossier(db, snapshot_id, _hops(db, snap, cluster, policy), rows, name, tier)
    group = db.scalar(select(AssetGroup).where(AssetGroup.name == name))
    return Dossier(
        system=DossierSystem(
            id=system,
            name=name,
            tier=tier,
            kind=group.kind if group is not None else "entry",
            owner=group.owner if group is not None else "",
            description=group.description if group is not None else "",
            components=result["components"],
        ),
        inbound=result["inbound"],
        outbound=result["outbound"],
        summary=result["summary"],
    )
