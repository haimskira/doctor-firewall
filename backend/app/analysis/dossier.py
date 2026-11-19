"""System dossier: one asset-table system at the centre, who reaches it and what it reaches.

Built on the permit flows of the attack-surface module (:func:`app.analysis.attack.load_hops`):
enabled ALLOW / TRUST access rules and prefilter FASTPATH rules that can match (shadowed rules
never do), zone-narrowed, plus a permitting default action. One flow is one rule.

* **Inbound** — flows whose destination overlaps the system; the peers are their sources.
* **Outbound** — flows whose source overlaps the system; the peers are their destinations.
* **Internal** — flows between the system's own addresses on both sides (counted, not drawn).

A peer is what the *rule* names on the other side, so a computer that is in no asset still
shows up, under its FMC object name (or as the literal address the rule holds):

* ``system`` — another asset-table system the other side's addresses touch;
* ``object`` — an FMC object (host / network / range / group / FQDN) or a literal on the other
  side that is not entirely inside asset-table systems (an unclassified computer or network);
* ``network`` — the other side is "any" but the rule's zones narrow it to routed networks;
* ``any`` — the other side is any address; ``default`` — the policy's default action permits.

Each arrow lists the services as protocol and port (``TCP-443``, ``UDP-53``) and the
applications. A flow is ``broad`` when its side at the system is wider than the system (the
rule was written for a larger network or for any): the system is reachable, but not by a rule
made for it. SGT / dynamic-object / user conditions are kept on the rules ("only for ...").
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.assets import AssetRow
from app.analysis.attack import Hop, cidrs
from app.analysis.expand import Resolver
from app.analysis.score import AssetIndex
from app.analysis.space import ALL_PROTOCOLS, AddressSet, PortSet
from app.models.inventory import RuleRef

Direction = Literal["inbound", "outbound"]
MAX_PEERS = 300  # per direction; the page says when it cut
RULE_SAMPLE = 25  # rules listed per peer (the count is exact)
SIDE_FIELD = {"inbound": "src_net", "outbound": "dst_net"}
KIND_ORDER = {"system": 0, "object": 1, "network": 2, "any": 3, "default": 4}
RISK_ORDER = {"green": 0, "yellow": 1, "red": 2}
ADDRESS_LITERALS = ("address", "range")


def port_labels(ports: PortSet) -> tuple[str, ...]:
    """``TCP-443``, ``UDP-53``, ``TCP-8080-8090``, ``TCP-any``, ``ICMP-8`` ... or ``any``."""
    if ports.any:
        return ("any",)
    out: list[str] = []
    for proto, intervals in ports.by_protocol:
        name = "IP" if proto == ALL_PROTOCOLS else proto
        for lo, hi in intervals:
            if (lo, hi) == (0, 65535):
                out.append(f"{name}-any")
            else:
                out.append(f"{name}-{lo}" if lo == hi else f"{name}-{lo}-{hi}")
    for token in sorted(ports.tokens):
        proto, sep, rest = token.partition("/")
        if sep and proto.isalpha() and proto.isupper():
            out.append(f"{proto}-{rest}" if rest and rest != "any" else proto)
    return tuple(out) or ("any",)


@dataclass
class Peer:
    key: str
    kind: str
    label: str
    tier: str | None = None
    values: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    apps: list[str] = field(default_factory=list)
    conditions: set[tuple[str, str]] = field(default_factory=set)
    rules: list[dict[str, Any]] = field(default_factory=list)
    rule_ids: set[str] = field(default_factory=set)
    hits: int = 0
    hits_known: bool = False
    risk: str = "green"
    broad: int = 0  # rules wider than the system at its side
    specific: int = 0
    inspected: int = 0
    targets: set[str] = field(default_factory=set)  # the system's components it touches

    def add(self, hop: Hop, ports: tuple[str, ...], broad: bool, targets: set[str]) -> None:
        if hop.fmc_id in self.rule_ids:
            self.targets |= targets
            return
        self.rule_ids.add(hop.fmc_id)
        for label in ports:
            if label not in self.services:
                self.services.append(label)
        for app in hop.apps:
            if app not in self.apps:
                self.apps.append(app)
        self.conditions |= set(hop.conditions)
        if hop.hits is not None:
            self.hits += hop.hits
            self.hits_known = True
        if RISK_ORDER[hop.risk] > RISK_ORDER[self.risk]:
            self.risk = hop.risk
        if broad:
            self.broad += 1
        else:
            self.specific += 1
        if hop.inspected:
            self.inspected += 1
        self.targets |= targets
        if len(self.rules) < RULE_SAMPLE:
            self.rules.append(
                {**hop.describe(), "risk": hop.risk, "broad": broad, "services": list(ports)}
            )

    def out(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "label": self.label,
            "tier": self.tier,
            "values": self.values,
            "services": self.services,
            "apps": self.apps,
            "conditions": [{"field": f, "name": n} for f, n in sorted(self.conditions)],
            "rule_count": len(self.rule_ids),
            "rules": sorted(self.rules, key=lambda r: (str(r["policy"]), int(r["index"]))),
            "hits": self.hits if self.hits_known else None,
            "risk": self.risk,
            "broad": self.broad,
            "specific": self.specific,
            "inspected": self.inspected,
            "targets": sorted(self.targets),
        }


class _SideRefs:
    """Per rule: what it names on one side — (key, label, values, addresses) per reference."""

    def __init__(self, session: Session, snapshot_id: int, rule_ids: set[int]) -> None:
        self._by_rule: dict[tuple[int, str], list[tuple[str, str, AddressSet]]] = defaultdict(list)
        if not rule_ids:
            return
        resolver: Resolver | None = None
        rows = session.execute(
            select(
                RuleRef.rule_id,
                RuleRef.field,
                RuleRef.object_fmc_id,
                RuleRef.object_name,
                RuleRef.literal,
                RuleRef.literal_kind,
            )
            .where(
                RuleRef.snapshot_id == snapshot_id,
                RuleRef.rule_id.in_(rule_ids),
                RuleRef.field.in_(tuple(SIDE_FIELD.values())),
            )
            .order_by(RuleRef.id)
        ).all()
        for rule_id, fld, object_id, name, literal, literal_kind in rows:
            if object_id is not None:
                if resolver is None:
                    resolver = Resolver.load(session, snapshot_id)
                leaves = resolver.leaves(object_id)
                addresses = AddressSet.build(leaves.addresses, leaves.address_tokens)
                self._by_rule[(rule_id, fld)].append((f"obj:{object_id}", name or "?", addresses))
            elif literal is not None and literal_kind in ADDRESS_LITERALS:
                addresses = AddressSet.build([literal])
                self._by_rule[(rule_id, fld)].append((f"lit:{literal}", literal, addresses))

    def get(self, rule_id: int, fld: str) -> list[tuple[str, str, AddressSet]]:
        return self._by_rule.get((rule_id, fld), [])


def _peer(found: dict[str, Peer], key: str, kind: str, label: str, **extra: Any) -> Peer:
    if key not in found:
        found[key] = Peer(key=key, kind=kind, label=label, **extra)
    return found[key]


def _within(inner: AddressSet, outer: AddressSet) -> bool:
    return not inner.any and not inner.tokens and outer.covers(inner)


def build_dossier(
    session: Session,
    snapshot_id: int,
    hops: list[Hop],
    rows: list[AssetRow],
    system: str,
    tier: str,
) -> dict[str, Any]:
    """The dossier of the system ``system`` (an asset name of the effective asset table)."""
    mine = [r for r in rows if r.system == system and r.tier == tier]
    networks = AddressSet.build([r.network for r in mine])
    components = [(r.component, AddressSet.build([r.network])) for r in mine]
    others = AssetIndex(
        [(r.network, r.system, r.tier, r.user_type) for r in rows if r.system != system]
    )
    everything = AssetIndex([(r.network, r.system, r.tier, r.user_type) for r in rows])
    system_networks: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in rows:
        system_networks[(r.tier, r.system)].append(r.network)

    touching: list[tuple[Direction, Hop]] = []
    internal = 0
    for hop in hops:
        into = hop.dst.intersects(networks)
        out_of = hop.src.intersects(networks)
        if into and out_of and _within(hop.src, networks) and _within(hop.dst, networks):
            internal += 1
            continue
        if into and not _within(hop.src, networks):
            touching.append(("inbound", hop))
        if out_of and not _within(hop.dst, networks):
            touching.append(("outbound", hop))
    refs = _SideRefs(session, snapshot_id, {h.rule_id for _, h in touching if h.rule_id})

    peers: dict[Direction, dict[str, Peer]] = {"inbound": {}, "outbound": {}}
    for direction, hop in touching:
        local, other = (hop.dst, hop.src) if direction == "inbound" else (hop.src, hop.dst)
        broad = not _within(local, networks)
        hit = local.intersection(networks)
        targets = {name for name, net in components if net.intersects(hit)}
        ports = port_labels(hop.ports) if hop.ports is not None else hop.services
        found = peers[direction]
        if hop.default:
            _peer(found, f"default:{hop.policy_fmc_id}", "default", hop.policy_name).add(
                hop, ports, broad, targets
            )
            continue
        if other.any:
            _peer(found, "any", "any", "any").add(hop, ports, broad, targets)
            continue
        for entry in others.touching(other):
            node = f"sys:{entry.tier}|{entry.system}"
            values = system_networks[(entry.tier, entry.system)]
            p = _peer(found, node, "system", entry.system, tier=entry.tier, values=values[:6])
            p.add(hop, ports, broad, targets)
        named = refs.get(hop.rule_id, SIDE_FIELD[direction])
        if not named:
            # "any" on that side, narrowed by the rule's zones to the networks behind them.
            if everything.unclassified(AddressSet(v4=other.v4, v6=other.v6)) or other.tokens:
                values = cidrs(other)
                p = _peer(found, f"net:{'|'.join(values)}", "network", "", values=values)
                p.add(hop, ports, broad, targets)
            continue
        for key, label, addresses in named:
            if _within(addresses, networks):
                continue  # the system's own address on the other side
            concrete = AddressSet(v4=addresses.v4, v6=addresses.v6)
            if not addresses.tokens and not everything.unclassified(concrete):
                continue  # entirely inside asset systems: shown as those systems
            p = _peer(found, key, "object", label, values=cidrs(addresses))
            p.add(hop, ports, broad, targets)

    def ordered(found: dict[str, Peer]) -> tuple[list[dict[str, Any]], bool]:
        items = sorted(
            found.values(),
            key=lambda p: (
                KIND_ORDER.get(p.kind, 9),
                -RISK_ORDER[p.risk],
                -(p.hits or 0),
                p.label.lower(),
            ),
        )
        return [p.out() for p in items[:MAX_PEERS]], len(items) > MAX_PEERS

    inbound, in_cut = ordered(peers["inbound"])
    outbound, out_cut = ordered(peers["outbound"])
    return {
        "components": [
            {
                "name": r.component,
                "network": r.network,
                "role": r.system_type,
                "ports": r.ports,
            }
            for r in mine
        ],
        "inbound": inbound,
        "outbound": outbound,
        "summary": {
            "inbound_peers": len(peers["inbound"]),
            "outbound_peers": len(peers["outbound"]),
            "inbound_rules": len({h.fmc_id for d, h in touching if d == "inbound"}),
            "outbound_rules": len({h.fmc_id for d, h in touching if d == "outbound"}),
            "internal_rules": internal,
            "truncated": in_cut or out_cut,
        },
    }
