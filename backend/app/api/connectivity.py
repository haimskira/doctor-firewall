"""Phase 4: the connectivity map (read-only)."""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.assets import effective_assets
from app.analysis.connectivity import ANY, RISK_ORDER, SERVER_TIERS, UNCLASSIFIED, node_tier
from app.analysis.space import AddressSet
from app.api.scope import PolicyQuery, enforced
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.fmc import normalize
from app.models.inventory import ClusterPolicy, Snapshot
from app.models.map import MapEdge

router = APIRouter(prefix="/api", tags=["map"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
CidrQuery = Annotated[str | None, Query(max_length=96)]
MAX_EDGES = 5000


class MapNode(BaseModel):
    id: str
    label: str
    tier: str | None
    user_type: str | None
    networks: list[str]


class MapEdgeOut(BaseModel):
    id: str
    src: str
    dst: str
    risk: str
    rule_count: int
    hits: int
    min_score: int | None
    reasons: list[str]
    services: list[str]
    rules: list[dict[str, Any]]
    # Rules / hits per risk colour (green, yellow, red); empty for snapshots before 0013.
    risk_rules: dict[str, int]
    risk_hits: dict[str, int]


class MapOut(BaseModel):
    view: str
    nodes: list[MapNode]
    edges: list[MapEdgeOut]
    total_edges: int
    truncated: bool
    risk_counts: dict[str, int]


def _filter_set(value: str | None, name: str) -> AddressSet | None:
    if value is None or value.strip() == "":
        return None
    text = value.strip()
    try:
        canonical = normalize.ip_range(text) if "-" in text else normalize.address(text)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid_{name}") from exc
    return AddressSet.build([canonical])


def _in_view(view: str, src: str, dst: str) -> bool:
    src_tier, dst_tier = node_tier(src), node_tier(dst)
    if view == "system":
        return src_tier in SERVER_TIERS and dst_tier in SERVER_TIERS
    if view == "users":
        return (src_tier == "USERS" or src == ANY) and dst_tier != "USERS"
    return True


@router.get("/snapshots/{snapshot_id}/map", response_model=MapOut)
def connectivity_map(
    snapshot_id: int,
    db: DbDep,
    _: ReaderDep,
    view: Literal["assets", "system", "users"] = "assets",
    cluster: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")] = None,
    policy: PolicyQuery = None,
    src: CidrQuery = None,
    dst: CidrQuery = None,
    both: bool = False,
    risk: Annotated[list[Literal["green", "yellow", "red"]] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_EDGES)] = 1500,
) -> MapOut:
    """Who talks to whom: aggregated edges between asset systems, worst risk first.

    ``src`` / ``dst`` (IP, CIDR or range) keep edges whose node networks intersect them;
    ``both`` also keeps the reverse direction. ``ANY`` matches every filter.
    """
    if db.get(Snapshot, snapshot_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    src_filter, dst_filter = _filter_set(src, "src"), _filter_set(dst, "dst")
    query = select(MapEdge).where(MapEdge.snapshot_id == snapshot_id)
    if policy is not None:  # one policy, enforced or not ("what would it allow")
        query = query.where(MapEdge.policy_fmc_id == policy)
    else:  # what the devices enforce: an unassigned policy opens nothing
        query = query.where(MapEdge.policy_fmc_id.in_(enforced(snapshot_id)))
    if cluster is not None:
        query = query.where(
            MapEdge.policy_fmc_id.in_(
                select(ClusterPolicy.policy_fmc_id).where(
                    ClusterPolicy.snapshot_id == snapshot_id,
                    ClusterPolicy.cluster_fmc_id == cluster,
                )
            )
        )

    # Node networks from the current (confirmed) asset table.
    networks: dict[str, list[str]] = defaultdict(list)
    user_types: dict[str, str | None] = {}
    for a in effective_assets(db):
        nid = f"{a.tier}|{a.system}"
        networks[nid].append(a.network)
        user_types.setdefault(nid, a.user_type)
    node_sets = {nid: AddressSet.build(nets) for nid, nets in networks.items()}
    covered = AddressSet.build([n for nets in networks.values() for n in nets])

    def matches(node: str, wanted: AddressSet | None) -> bool:
        if wanted is None or node == ANY:
            return True
        if node == UNCLASSIFIED:
            return not covered.covers(wanted)
        found = node_sets.get(node)
        return found is not None and found.intersects(wanted)

    def selected(s: str, d: str) -> bool:
        if matches(s, src_filter) and matches(d, dst_filter):
            return True
        return both and matches(d, src_filter) and matches(s, dst_filter)

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for e in db.scalars(query):
        if not _in_view(view, e.src_node, e.dst_node) or not selected(e.src_node, e.dst_node):
            continue
        cur = merged.get((e.src_node, e.dst_node))
        if cur is None:
            merged[(e.src_node, e.dst_node)] = {
                "risk": e.risk,
                "rule_count": e.rule_count,
                "hits": e.hits,
                "min_score": e.min_score,
                "reasons": set(e.reasons),
                "services": list(e.services),
                "rules": [{**r, "policy_id": e.policy_fmc_id} for r in e.rules],
                "risk_rules": dict(e.risk_rules or {}),
                "risk_hits": dict(e.risk_hits or {}),
            }
            continue
        cur["risk"] = max(cur["risk"], e.risk, key=RISK_ORDER.__getitem__)
        cur["rule_count"] += e.rule_count
        cur["hits"] += e.hits
        if e.min_score is not None:
            cur["min_score"] = (
                e.min_score if cur["min_score"] is None else min(cur["min_score"], e.min_score)
            )
        cur["reasons"] |= set(e.reasons)
        cur["services"] += [x for x in e.services if x not in cur["services"]][:20]
        cur["rules"] += [{**r, "policy_id": e.policy_fmc_id} for r in e.rules][:20]
        for key, part in (("risk_rules", e.risk_rules), ("risk_hits", e.risk_hits)):
            for colour, value in (part or {}).items():
                cur[key][colour] = cur[key].get(colour, 0) + value

    counts = {"green": 0, "yellow": 0, "red": 0}
    for v in merged.values():
        counts[v["risk"]] += 1
    wanted_risks = set(risk) if risk else set(counts)
    ordered = sorted(
        ((k, v) for k, v in merged.items() if v["risk"] in wanted_risks),
        key=lambda kv: (-RISK_ORDER[kv[1]["risk"]], -kv[1]["rule_count"], kv[0]),
    )
    total = len(ordered)
    ordered = ordered[:limit]
    edges = [
        MapEdgeOut(
            id=f"{s}->{d}",
            src=s,
            dst=d,
            risk=v["risk"],
            rule_count=v["rule_count"],
            hits=v["hits"],
            min_score=v["min_score"],
            reasons=sorted(v["reasons"]),
            services=v["services"][:20],
            rules=v["rules"][:20],
            risk_rules=v["risk_rules"],
            risk_hits=v["risk_hits"],
        )
        for (s, d), v in ordered
    ]
    used = sorted({e.src for e in edges} | {e.dst for e in edges})
    nodes = [
        MapNode(
            id=n,
            label=n.split("|", 1)[1] if "|" in n else n,
            tier=node_tier(n),
            user_type=user_types.get(n),
            networks=networks.get(n, [])[:10],
        )
        for n in used
    ]
    return MapOut(
        view=view,
        nodes=nodes,
        edges=edges,
        total_edges=total,
        truncated=total > len(edges),
        risk_counts=counts,
    )
