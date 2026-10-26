"""Phase 4: the connectivity map — who talks to whom, coloured by risk.

Nodes are the systems of the (confirmed) asset table, ``TIER|SYSTEM``, plus two special
nodes: ``ANY`` (a rule side without addresses = any) and ``UNCLASSIFIED`` (addresses that no
asset covers, FQDNs, SGTs, dynamic objects, users). Every enabled permit access rule that can
match (not shadowed) adds an edge from each source node to each destination node.

Risk of a rule (doctrine colours, docs/connectivity.md):

* red — a clear breach: tier skip (bronze -> gold), any -> any, or a dead rule still open;
* yellow — works but deviates from the ideal: GOLD/SILVER without inspection, any or wide
  service, broad or any source / destination, several destination tiers;
* green — compliant.

An edge carries the worst risk of its rules, their count, the hits, the lowest score and a
sample of rules and services. Edges are stored per policy so a cluster filter is exact.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from app.analysis.score import AssetIndex
from app.analysis.space import AddressSet
from app.models.inventory import Rule, RuleRef
from app.models.map import MapEdge

ANY = "ANY"
UNCLASSIFIED = "UNCLASSIFIED"
SERVER_TIERS = frozenset({"CORE", "GOLD", "SILVER", "BRONZE"})
RISK_ORDER = {"green": 0, "yellow": 1, "red": 2}
RED_REASONS = frozenset({"tier_skip", "dead"})
YELLOW_REASONS = frozenset(
    {
        "gold_without_ips",
        "gold_without_file_policy",
        "silver_without_ips",
        "gold_many_sources",
        "any_service",
        "wide_ports",
        "any_destination",
        "any_source",
        "broad_destination",
        "broad_source",
        "multi_tier_destination",
    }
)
SAMPLE = 20


def rule_risk(reason_codes: Iterable[str]) -> str:
    codes = set(reason_codes)
    if codes & RED_REASONS or {"any_source", "any_destination"} <= codes:
        return "red"
    if codes & YELLOW_REASONS:
        return "yellow"
    return "green"


def worst(a: str, b: str) -> str:
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


def node_id(tier: str, system: str) -> str:
    return f"{tier}|{system}"


def node_tier(node: str) -> str | None:
    return node.split("|", 1)[0] if "|" in node else None


class NodeMapper:
    """Address set -> map nodes, memoised (many rules share the same groups)."""

    def __init__(self, assets: AssetIndex) -> None:
        self.assets = assets
        self._cache: dict[AddressSet, tuple[str, ...]] = {}

    def nodes(self, addresses: AddressSet) -> tuple[str, ...]:
        if addresses.any:
            return (ANY,)
        cached = self._cache.get(addresses)
        if cached is not None:
            return cached
        found = {node_id(e.tier, e.system) for e in self.assets.touching(addresses)}
        concrete = AddressSet(v4=addresses.v4, v6=addresses.v6)
        if addresses.tokens or (
            (addresses.v4 or addresses.v6)
            and (not len(self.assets) or self.assets.unclassified(concrete))
        ):
            found.add(UNCLASSIFIED)
        if not found:
            found.add(UNCLASSIFIED)
        result = tuple(sorted(found))
        self._cache[addresses] = result
        return result


def edges_for(
    mapper: NodeMapper, src: AddressSet, dst: AddressSet, risk: str
) -> list[dict[str, str]]:
    """Node-level edges of one rule (used by recommendation before / after previews)."""
    return [
        {"src": s, "dst": d, "risk": risk} for s in mapper.nodes(src) for d in mapper.nodes(dst)
    ]


@dataclass
class _Edge:
    rule_count: int = 0
    hits: int = 0
    min_score: int | None = None
    risk: str = "green"
    reasons: set[str] = field(default_factory=set)
    rules: list[dict[str, Any]] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    risk_rules: dict[str, int] = field(default_factory=dict)
    risk_hits: dict[str, int] = field(default_factory=dict)


class MapBuilder:
    """Collects edges during the phase-2 analysis loop; one flush per snapshot."""

    def __init__(self, session: Session, snapshot_id: int, assets: AssetIndex) -> None:
        self.session = session
        self.snapshot_id = snapshot_id
        self.mapper = NodeMapper(assets)
        self._edges: dict[tuple[str, str, str], _Edge] = {}
        self._services: dict[int, list[str]] = {}

    def load_services(self, policy_id: str) -> None:
        """Ports / applications / URLs per rule of a policy (labels as in the FMC)."""
        labels: dict[int, list[str]] = defaultdict(list)
        for rule_id, name, literal in self.session.execute(
            select(RuleRef.rule_id, RuleRef.object_name, RuleRef.literal)
            .join(Rule, Rule.id == RuleRef.rule_id)
            .where(
                RuleRef.snapshot_id == self.snapshot_id,
                RuleRef.field.in_(("dst_port", "app", "url")),
                Rule.policy_fmc_id == policy_id,
            )
            .order_by(RuleRef.id)
        ).all():
            label = literal if literal is not None else name
            if label and label not in labels[rule_id]:
                labels[rule_id].append(label)
        self._services = dict(labels)

    def add(
        self,
        *,
        policy_id: str,
        rule: dict[str, Any],
        rule_id: int,
        src: AddressSet,
        dst: AddressSet,
        reasons: Iterable[str],
        score: int | None,
        hits: int | None,
    ) -> None:
        codes = set(reasons)
        risk = rule_risk(codes)
        services = self._services.get(rule_id) or ["any"]
        for s in self.mapper.nodes(src):
            for d in self.mapper.nodes(dst):
                edge = self._edges.setdefault((policy_id, s, d), _Edge())
                edge.rule_count += 1
                edge.hits += hits or 0
                if score is not None:
                    edge.min_score = score if edge.min_score is None else min(edge.min_score, score)
                edge.risk = worst(edge.risk, risk)
                edge.risk_rules[risk] = edge.risk_rules.get(risk, 0) + 1
                edge.risk_hits[risk] = edge.risk_hits.get(risk, 0) + (hits or 0)
                edge.reasons |= codes & (RED_REASONS | YELLOW_REASONS)
                if len(edge.rules) < SAMPLE:
                    edge.rules.append({**rule, "risk": risk, "score": score})
                for label in services:
                    if label not in edge.services and len(edge.services) < SAMPLE:
                        edge.services.append(label)

    def flush(self) -> int:
        self.session.execute(delete(MapEdge).where(MapEdge.snapshot_id == self.snapshot_id))
        if self._edges:
            self.session.execute(
                insert(MapEdge),
                [
                    {
                        "snapshot_id": self.snapshot_id,
                        "policy_fmc_id": policy_id,
                        "src_node": s,
                        "dst_node": d,
                        "rule_count": e.rule_count,
                        "hits": e.hits,
                        "min_score": e.min_score,
                        "risk": e.risk,
                        "reasons": sorted(e.reasons),
                        "rules": e.rules,
                        "services": e.services,
                        "risk_rules": e.risk_rules,
                        "risk_hits": e.risk_hits,
                    }
                    for (policy_id, s, d), e in self._edges.items()
                ],
            )
        return len(self._edges)
