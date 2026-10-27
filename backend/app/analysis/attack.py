"""Attack surface and blast radius: every way the rulebase lets traffic reach a target.

A **hop** is a flow one permit rule allows: an enabled ALLOW / TRUST access rule or a prefilter
FASTPATH rule that can match (shadowed rules never do), from its source addresses to its
destination addresses, with its services and applications. A policy whose default action
permits adds an ``any -> any`` hop for everything its rules do not decide.

* **Paths to a target** (``mode="to"``): who can reach the target directly; who can reach
  those sources; and so on, up to ``depth`` hops. ``C -> B -> A`` is a path only when the
  addresses of B that C may reach overlap the addresses of B allowed to reach A — pivoting is
  checked on address sets, not on system names.
* **Blast radius** (``mode="from"``): everything a compromised source reaches, then everything
  those destinations reach, and so on.

The search runs on address sets (the sources / destinations of rules) and is then shown on the
asset systems of the connectivity map. Traffic inside one network never crosses the firewall
and is not a hop. An earlier rule with the opposite verdict that overlaps a hop's rule marks
the hop ``partial`` (part of that traffic is decided earlier). Rules are evaluated per policy;
prefilter decisions in front of an access policy are not subtracted (documented limitation).
Every search is capped (depth, frontier, edges, paths) and says when it was truncated.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.connectivity import (
    ANY,
    UNCLASSIFIED,
    NodeMapper,
    node_id,
    node_tier,
    rule_risk,
)
from app.analysis.expand import Resolver, rule_spaces
from app.analysis.score import AssetIndex
from app.analysis.space import AddressSet
from app.models.assets import RuleScore
from app.models.inventory import ClusterPolicy, Finding, FwObject, Policy, Rule, RuleRef

Mode = Literal["to", "from"]

MAX_DEPTH = 4
MAX_FRONTIER = 400  # distinct address sets expanded per layer
MAX_PATHS = 2000
MAX_EDGES = 1500
PERMIT_ACTIONS = {"access": {"ALLOW", "TRUST"}, "prefilter": {"FASTPATH"}}
PERMIT_DEFAULTS = {"PERMIT", "TRUST", "NETWORK_DISCOVERY", "ALLOW"}
ENTRY_WEIGHT = {ANY: 100, "USERS": 80, "BRONZE": 70, UNCLASSIFIED: 60, "SILVER": 40}
TIER_RANK = {"CORE": 4, "GOLD": 3, "SILVER": 2, "BRONZE": 1, "USERS": 0}
RISK_ORDER = {"green": 0, "yellow": 1, "red": 2}


@dataclass(frozen=True)
class Hop:
    """One permit rule as a flow."""

    rule_id: int
    fmc_id: str
    name: str
    index: int
    policy_fmc_id: str
    policy_name: str
    action: str
    src: AddressSet
    dst: AddressSet
    services: tuple[str, ...]
    apps: tuple[str, ...]
    inspected: bool
    partial: bool
    risk: str
    hits: int | None
    default: bool = False
    # Identity conditions the addresses alone do not show (SGT, dynamic object, user): the
    # hop exists only for endpoints that also match them. ((field, name), ...)
    conditions: tuple[tuple[str, str], ...] = ()

    def describe(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_fmc_id,
            "policy": self.policy_name,
            "id": self.fmc_id,
            "name": self.name,
            "index": self.index,
            "action": self.action,
            "inspected": self.inspected,
            "partial": self.partial,
            "default": self.default,
            "hits": self.hits,
            "conditions": [{"field": f, "name": n} for f, n in self.conditions],
        }


@dataclass
class _Edge:
    """From the search's ``near`` set (already reached) one step further, to ``far``.

    ``met`` is the part of ``near`` the hops touch. Traffic flows ``far -> met`` when
    searching paths to a target and ``met -> far`` when searching a blast radius.
    """

    near: AddressSet
    far: AddressSet
    met: AddressSet
    depth: int
    hops: list[Hop] = field(default_factory=list)

    def flow(self, mode: Mode) -> tuple[AddressSet, AddressSet]:
        return (self.far, self.met) if mode == "to" else (self.met, self.far)


@dataclass
class Surface:
    """Result of one search, still on address sets (``describe`` maps it to systems)."""

    mode: Mode
    origin: AddressSet
    depth: int
    edges: list[_Edge]
    truncated: bool


def load_hops(session: Session, snapshot_id: int, cluster: str | None = None) -> list[Hop]:
    """Every permit flow of the snapshot (of one cluster's policies if ``cluster``)."""
    policies = list(
        session.scalars(
            select(Policy).where(
                Policy.snapshot_id == snapshot_id, Policy.kind.in_(tuple(PERMIT_ACTIONS))
            )
        )
    )
    if cluster is not None:
        governing = set(
            session.scalars(
                select(ClusterPolicy.policy_fmc_id).where(
                    ClusterPolicy.snapshot_id == snapshot_id,
                    ClusterPolicy.cluster_fmc_id == cluster,
                )
            )
        )
        policies = [p for p in policies if p.fmc_id in governing]
    if not policies:
        return []
    scores = {
        rule_id: (shadowed_by, [str(r.get("code")) for r in reasons if isinstance(r, dict)])
        for rule_id, shadowed_by, reasons in session.execute(
            select(RuleScore.rule_id, RuleScore.shadowed_by, RuleScore.reasons).where(
                RuleScore.snapshot_id == snapshot_id
            )
        )
    }
    partial: set[str] = set()
    for details in session.scalars(
        select(Finding.details).where(
            Finding.snapshot_id == snapshot_id, Finding.kind == "overlap_conflict"
        )
    ):
        rule = details.get("rule")
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            partial.add(rule["id"])
    labels = _service_labels(session, snapshot_id)
    condition_labels = _condition_labels(session, snapshot_id)
    inspected = {
        rule_id: ips is not None
        for rule_id, ips in session.execute(
            select(Rule.id, Rule.ips_policy_id).where(Rule.snapshot_id == snapshot_id)
        )
    }
    resolver = Resolver.load(session, snapshot_id)
    hops: list[Hop] = []
    for policy in policies:
        allowed = PERMIT_ACTIONS[policy.kind]
        for rs in rule_spaces(session, snapshot_id, policy.fmc_id, resolver):
            if not rs.enabled or rs.action not in allowed:
                continue
            shadowed_by, reasons = scores.get(rs.rule_id, (None, []))
            if shadowed_by is not None:
                continue
            services, apps = labels.get(rs.rule_id, ((), ()))
            conditions = condition_labels.get(rs.rule_id, ())
            hops.append(
                Hop(
                    rule_id=rs.rule_id,
                    fmc_id=rs.fmc_id,
                    name=rs.name,
                    index=rs.rule_index,
                    policy_fmc_id=policy.fmc_id,
                    policy_name=policy.name,
                    action=rs.action,
                    src=rs.space.src_net,
                    dst=rs.space.dst_net,
                    services=services or ("any",),
                    apps=apps,
                    inspected=inspected.get(rs.rule_id, False),
                    partial=rs.fmc_id in partial,
                    risk=rule_risk(reasons),
                    hits=rs.hit_count,
                    conditions=conditions,
                )
            )
        if policy.kind == "access" and policy.default_action.upper() in PERMIT_DEFAULTS:
            hops.append(
                Hop(
                    rule_id=0,
                    fmc_id=f"default:{policy.fmc_id}",
                    name="Default action",
                    index=0,
                    policy_fmc_id=policy.fmc_id,
                    policy_name=policy.name,
                    action=policy.default_action.upper(),
                    src=AddressSet(any=True),
                    dst=AddressSet(any=True),
                    services=("any",),
                    apps=(),
                    inspected=False,
                    partial=True,  # only what no rule decided before it
                    risk="red",
                    hits=None,
                    default=True,
                )
            )
    return hops


def _service_labels(
    session: Session, snapshot_id: int
) -> dict[int, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Per rule: its destination services and applications as the FMC names them."""
    services: dict[int, set[str]] = defaultdict(set)
    apps: dict[int, set[str]] = defaultdict(set)
    for rule_id, fld, name, literal in session.execute(
        select(RuleRef.rule_id, RuleRef.field, FwObject.name, RuleRef.literal)
        .outerjoin(
            FwObject,
            (FwObject.snapshot_id == RuleRef.snapshot_id)
            & (FwObject.fmc_id == RuleRef.object_fmc_id),
        )
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.field.in_(("dst_port", "app")))
    ):
        (services if fld == "dst_port" else apps)[rule_id].add(str(name or literal or "?"))
    return {
        k: (tuple(sorted(services.get(k, set()))), tuple(sorted(apps.get(k, set()))))
        for k in set(services) | set(apps)
    }


CONDITION_FIELDS = ("src_sgt", "dst_sgt", "src_dyn", "dst_dyn", "user")


def _condition_labels(session: Session, snapshot_id: int) -> dict[int, tuple[tuple[str, str], ...]]:
    """Per rule: its SGT / dynamic object / user conditions, as the FMC names them."""
    out: dict[int, set[tuple[str, str]]] = defaultdict(set)
    for rule_id, fld, name, literal in session.execute(
        select(RuleRef.rule_id, RuleRef.field, FwObject.name, RuleRef.literal)
        .outerjoin(
            FwObject,
            (FwObject.snapshot_id == RuleRef.snapshot_id)
            & (FwObject.fmc_id == RuleRef.object_fmc_id),
        )
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.field.in_(CONDITION_FIELDS))
    ):
        out[rule_id].add((fld, str(name or literal or "?")))
    return {k: tuple(sorted(v)) for k, v in out.items()}


def _merge(a: AddressSet, b: AddressSet) -> AddressSet:
    if a.any or b.any:
        return AddressSet(any=True)
    out: list[str] = []
    for version, intervals in ((4, a.v4 + b.v4), (6, a.v6 + b.v6)):
        for lo, hi in intervals:
            start = ipaddress.IPv4Address(lo) if version == 4 else ipaddress.IPv6Address(lo)
            end = ipaddress.IPv4Address(hi) if version == 4 else ipaddress.IPv6Address(hi)
            out.append(f"{start}-{end}")
    return AddressSet.build(out, a.tokens | b.tokens)


def search(hops: Iterable[Hop], origin: AddressSet, mode: Mode, depth: int) -> Surface:
    """Layered search from ``origin`` (the target, or the compromised source)."""
    depth = max(1, min(depth, MAX_DEPTH))
    # Hops grouped by the side the search meets: destination ("to") or source ("from").
    groups: dict[AddressSet, list[Hop]] = defaultdict(list)
    for hop in hops:
        groups[hop.dst if mode == "to" else hop.src].append(hop)
    edges: dict[tuple[AddressSet, AddressSet], _Edge] = {}
    seen: set[AddressSet] = {origin}
    frontier = [origin]
    truncated = False
    for level in range(1, depth + 1):
        following: list[AddressSet] = []
        for near in frontier:
            for side, members in groups.items():
                met = side.intersection(near)
                if met.empty:
                    continue
                for hop in members:
                    far = hop.src if mode == "to" else hop.dst
                    if not far.any and origin.covers(far):
                        continue  # inside the origin itself: not a way in (or out)
                    edge = edges.get((near, far))
                    if edge is None:
                        if len(edges) >= MAX_EDGES:
                            truncated = True
                            continue
                        edge = _Edge(near=near, far=far, met=met, depth=level)
                        edges[(near, far)] = edge
                    elif not edge.met.covers(met):
                        edge.met = _merge(edge.met, met)
                    edge.hops.append(hop)
                    if not far.any and far not in seen:
                        seen.add(far)
                        following.append(far)
        if len(following) > MAX_FRONTIER:
            truncated = True
            following = following[:MAX_FRONTIER]
        frontier = following
        if not frontier:
            break
    return Surface(
        mode=mode, origin=origin, depth=depth, edges=list(edges.values()), truncated=truncated
    )


# ------------------------------------------------------------------ presentation


@dataclass
class _Path:
    """Origin first: ``sets[i]`` is ``i`` hops from the origin; ``edges[i]`` joins
    ``sets[i]`` and ``sets[i + 1]``."""

    sets: list[AddressSet]
    edges: list[_Edge]


def _paths(surface: Surface) -> tuple[list[_Path], bool]:
    """The shortest path to every address set the search reached (one per set; an entry from
    "anywhere" once per set it reaches), shortest first and capped."""
    best: dict[AddressSet, _Path] = {surface.origin: _Path(sets=[surface.origin], edges=[])}
    paths: list[_Path] = []
    for e in sorted(surface.edges, key=lambda e: e.depth):
        base = best.get(e.near)
        if base is None or e.far in base.sets:
            continue
        path = _Path(sets=[*base.sets, e.far], edges=[*base.edges, e])
        if not e.far.any:
            if e.far in best:
                continue
            best[e.far] = path
        paths.append(path)
        if len(paths) >= MAX_PATHS:
            return paths, True
    return paths, False


def cidrs(addresses: AddressSet, limit: int = 6) -> list[str]:
    """A readable sample of an address set (summarised networks)."""
    if addresses.any:
        return ["any"]
    out: list[str] = []
    for lo, hi in addresses.v4:
        out += [
            str(n)
            for n in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)
            )
        ]
    for lo, hi in addresses.v6:
        out += [
            str(n)
            for n in ipaddress.summarize_address_range(
                ipaddress.IPv6Address(lo), ipaddress.IPv6Address(hi)
            )
        ]
    out += sorted(addresses.tokens)
    return [*out[:limit], "…"] if len(out) > limit else out


def describe(surface: Surface, assets: AssetIndex, labels: dict[str, str]) -> dict[str, Any]:
    """Systems, the edges between them, ranked paths and a summary for the UI."""
    mode = surface.mode
    mapped = NodeMapper(assets).nodes
    # A blast radius that reaches "any" destination reaches every system (and the rest of
    # the world): show them all, not one "anywhere" dot.
    everything = (*sorted({node_id(e.tier, e.system) for e in assets.entries}), ANY)

    def nodes_of(addresses: AddressSet) -> tuple[str, ...]:
        if mode == "from" and addresses.any:
            return everything
        return mapped(addresses)

    origin_nodes = set(nodes_of(surface.origin))
    paths, paths_truncated = _paths(surface)

    node_depth: dict[str, int] = dict.fromkeys(origin_nodes, 0)
    node_nets: dict[str, set[str]] = defaultdict(set)
    edge_out: dict[tuple[str, str], dict[str, Any]] = {}
    # The map shows the whole search graph; the path list explains it one path per entry.
    for e in sorted(surface.edges, key=lambda e: e.depth):
        for n in nodes_of(e.far):
            node_depth[n] = min(node_depth.get(n, e.depth), e.depth)
        src, dst = e.flow(mode)
        for addresses in (src, dst):
            if addresses.any:
                continue  # "any" says nothing about a system's own networks
            for n in nodes_of(addresses):
                node_nets[n].update(cidrs(addresses, 3))
        for s in nodes_of(src):
            for d in nodes_of(dst):
                if s == d:
                    continue
                out = edge_out.setdefault(
                    (s, d),
                    {
                        "id": f"{s}->{d}",
                        "src": s,
                        "dst": d,
                        "depth": e.depth,
                        "services": set(),
                        "apps": set(),
                        "rules": {},
                        "risk": "green",
                    },
                )
                out["depth"] = min(out["depth"], e.depth)
                for hop in e.hops:
                    out["services"].update(hop.services)
                    out["apps"].update(hop.apps)
                    out["rules"].setdefault(hop.fmc_id, hop.describe())
                    if RISK_ORDER.get(hop.risk, 0) > RISK_ORDER.get(out["risk"], 0):
                        out["risk"] = hop.risk
    edges = [
        {
            **e,
            "services": sorted(e["services"]),
            "apps": sorted(e["apps"]),
            "rules": sorted(e["rules"].values(), key=lambda r: (r["policy"], r["index"]))[:20],
            "rule_count": len(e["rules"]),
        }
        for e in edge_out.values()
    ]

    def kind(n: str) -> str:
        if n in origin_nodes:
            return "origin"
        return {ANY: "anywhere", UNCLASSIFIED: "unclassified"}.get(n, "system")

    nodes = [
        {
            "id": n,
            "label": labels.get(n, n),
            "tier": node_tier(n),
            "kind": kind(n),
            "depth": d,
            "networks": sorted(node_nets.get(n, set()))[:6],
        }
        for n, d in node_depth.items()
    ]
    ranked = sorted(
        (_rank(p, mode, nodes_of) for p in paths), key=lambda r: (-r["score"], len(r["hops"]))
    )
    ends = {n for p in paths for n in nodes_of(p.sets[-1])} - origin_nodes
    services: dict[str, int] = defaultdict(int)
    for p in paths:
        for svc in {x for h in p.edges[0].hops for x in h.services}:
            services[svc] += 1
    return {
        "mode": mode,
        "origin": {"nodes": sorted(origin_nodes), "networks": cidrs(surface.origin)},
        "nodes": nodes,
        "edges": edges,
        "paths": ranked[:100],
        "summary": {
            "paths": len(paths),
            "entry_points": len(ends),
            "anywhere": any(p.sets[-1].any for p in paths),
            "shortest": min((len(p.edges) for p in paths), default=None),
            "services": [s for s, _ in sorted(services.items(), key=lambda x: (-x[1], x[0]))][:12],
            "reached": len([n for n in node_depth if n not in origin_nodes]),
            "truncated": surface.truncated or paths_truncated,
        },
    }


def _rank(
    path: _Path, mode: Mode, nodes_of: Callable[[AddressSet], tuple[str, ...]]
) -> dict[str, Any]:
    """Score a path (higher = more dangerous), say why, and lay it out in flow order."""
    far = path.sets[-1]  # the entry ("to") or the furthest reach ("from")
    reasons: list[str] = []
    if far.any:
        weight = ENTRY_WEIGHT[ANY]
        reasons.append("anywhere")
    elif mode == "to":
        weight = max(
            (ENTRY_WEIGHT.get(node_tier(n) or n, 30) for n in nodes_of(far)),
            default=ENTRY_WEIGHT[UNCLASSIFIED],
        )
    else:  # blast radius: reaching higher tiers is worse
        weight = 30 + 15 * max(
            (TIER_RANK.get(node_tier(n) or "", 0) for n in nodes_of(far)), default=0
        )
    hops = [h for e in path.edges for h in e.hops]
    score = weight - 10 * (len(path.edges) - 1)
    reasons.append("direct" if len(path.edges) == 1 else "pivot")
    if any(not h.inspected for h in hops):
        score += 10
        reasons.append("uninspected")
    if any("any" in h.services for h in hops):
        score += 10
        reasons.append("any_service")
    if any(h.default for h in hops):
        score += 10
        reasons.append("default_action")
    if all(all(h.partial for h in e.hops) for e in path.edges):
        score -= 5
        reasons.append("partly_blocked")
    flow_sets = list(reversed(path.sets)) if mode == "to" else list(path.sets)
    flow_edges = list(reversed(path.edges)) if mode == "to" else list(path.edges)
    tiers = [
        max((TIER_RANK.get(node_tier(n) or "", -1) for n in nodes_of(s)), default=-1)
        for s in flow_sets
    ]
    if any(b - a >= 2 for a, b in pairwise(tiers) if a >= 0):
        score += 15
        reasons.append("tier_skip")
    return {
        "score": score,
        "reasons": reasons,
        "steps": [{"nodes": list(nodes_of(s)), "networks": cidrs(s, 4)} for s in flow_sets],
        "hops": [
            {
                "services": sorted({x for h in e.hops for x in h.services})[:12],
                "apps": sorted({x for h in e.hops for x in h.apps})[:12],
                "rules": [h.describe() for h in e.hops[:10]],
                "rule_count": len(e.hops),
            }
            for e in flow_edges
        ],
    }
