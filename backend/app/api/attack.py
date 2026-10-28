"""Attack surface / blast radius of a snapshot's rulebase (read-only; see app.analysis.attack)."""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.assets import effective_assets
from app.analysis.attack import MAX_DEPTH, Hop, cidrs, describe, load_hops, search
from app.analysis.expand import Resolver
from app.analysis.score import AssetIndex
from app.analysis.space import AddressSet
from app.api.scope import PolicyQuery
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.fmc import normalize
from app.models.inventory import FwObject, Snapshot

router = APIRouter(prefix="/api", tags=["attack-surface"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
ClusterQuery = Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
ADDRESS_KINDS = ("host", "network", "range", "fqdn", "network_group")


class AttackSurface(BaseModel):
    mode: str
    origin: dict[str, Any]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    paths: list[dict[str, Any]]
    summary: dict[str, Any]


class TargetSystem(BaseModel):
    id: str
    label: str
    tier: str
    networks: list[str]


# Hops of a snapshot are immutable until it is analysed again: keep a few in memory.
_CACHE: OrderedDict[tuple[int, str | None, datetime | None], list[Hop]] = OrderedDict()
_CACHE_SIZE = 4
_LOCK = threading.Lock()


def _hops(
    db: Session, snapshot: Snapshot, cluster: str | None, policy: str | None = None
) -> list[Hop]:
    key = (snapshot.id, f"{cluster}|{policy}", snapshot.analyzed_at)
    with _LOCK:
        if key in _CACHE:
            _CACHE.move_to_end(key)
            return _CACHE[key]
    hops = load_hops(db, snapshot.id, cluster, policy)
    with _LOCK:
        _CACHE[key] = hops
        while len(_CACHE) > _CACHE_SIZE:
            _CACHE.popitem(last=False)
    return hops


def _systems(db: Session) -> dict[str, TargetSystem]:
    found: dict[str, TargetSystem] = {}
    for a in effective_assets(db):
        node = f"{a.tier}|{a.system}"
        entry = found.setdefault(
            node, TargetSystem(id=node, label=a.system, tier=a.tier, networks=[])
        )
        entry.networks.append(a.network)
    return found


def _snapshot(db: Session, snapshot_id: int) -> Snapshot:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if snap.status != "complete" or snap.analyzed_at is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "snapshot_not_analyzed")
    return snap


def _bad(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail)


@router.get("/snapshots/{snapshot_id}/attack-surface/targets", response_model=list[TargetSystem])
def attack_targets(snapshot_id: int, db: DbDep, _: ReaderDep) -> list[TargetSystem]:
    """The systems of the asset table, to pick a target or a compromised source from."""
    _snapshot(db, snapshot_id)
    return sorted(_systems(db).values(), key=lambda s: (s.tier, s.label))


@router.get("/snapshots/{snapshot_id}/attack-surface", response_model=AttackSurface)
def attack_surface(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    mode: Literal["to", "from"] = "to",
    system: Annotated[str | None, Query(min_length=3, max_length=200)] = None,
    object_id: Annotated[
        str | None, Query(alias="object", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    ] = None,
    address: Annotated[str | None, Query(max_length=96)] = None,
    depth: Annotated[int, Query(ge=1, le=MAX_DEPTH)] = 3,
    cluster: ClusterQuery = None,
    policy: PolicyQuery = None,
) -> AttackSurface:
    """Every way the rulebase lets traffic reach the target (``mode=to``), or everything a
    compromised source reaches (``mode=from``), hop by hop with services and rules.

    The target is exactly one of: an asset-table ``system`` (``TIER|name``), an address
    ``object`` of the snapshot, or an ``address`` (IP, CIDR or range).
    """
    snap = _snapshot(db, snapshot_id)
    if sum(v is not None for v in (system, object_id, address)) != 1:
        raise _bad("target_required")
    systems = _systems(db)
    origin: AddressSet
    if system is not None:
        found = systems.get(system)
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_target")
        origin = AddressSet.build(found.networks)
    elif object_id is not None:
        obj = db.scalar(
            select(FwObject).where(
                FwObject.snapshot_id == snapshot_id, FwObject.fmc_id == object_id
            )
        )
        if obj is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_target")
        if obj.kind not in ADDRESS_KINDS:
            raise _bad("not_an_address")
        leaves = Resolver.load(db, snapshot_id).leaves(object_id)
        origin = AddressSet.build(leaves.addresses, leaves.address_tokens)
    else:
        text = (address or "").strip()
        try:
            canonical = normalize.ip_range(text) if "-" in text else normalize.address(text)
        except ValueError as exc:
            raise _bad("invalid_address") from exc
        origin = AddressSet.build([canonical])
    everything = AddressSet.build(["0.0.0.0/0"]).v4
    if origin.empty or origin.any or origin.v4 == everything:
        raise _bad("invalid_target")  # the whole internet is not a target
    surface = search(_hops(db, snap, cluster, policy), origin, mode, depth)
    assets = AssetIndex([(n, s.label, s.tier, None) for s in systems.values() for n in s.networks])
    labels = {node: s.label for node, s in systems.items()}
    result = describe(surface, assets, labels)
    result["origin"]["networks"] = cidrs(origin)
    return AttackSurface(**result)
