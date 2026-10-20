"""Rule score (0-100) against the doctrine, with an explanation for every deduction.

The score orders the optimisation queue and colours the connectivity map. It is never a
black box: each deduction is a (code, points, detail) entry the operator sees. Weights
are documented in docs/scoring.md; the doctrine principles behind them:

* the rule is anchored on its destination: "any" destination is the worst offence;
* generous with sources, stingy with destination and service;
* one destination tier per rule; GOLD = few, precise sources and full inspection;
* east-west only from less to more sensitive, never skipping (bronze -> gold is a breach);
* access and inspection are separate layers, crossed by the destination tier.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from app.analysis.space import AddressSet

TIER_RANK = {"BRONZE": 1, "SILVER": 2, "GOLD": 3}  # CORE sits outside the tiers
PERMIT_ACTIONS = frozenset({"ALLOW", "TRUST"})

BROAD_DESTINATION = 256  # addresses
BROAD_SOURCE = 65_536
GOLD_MANY_SOURCES = 1_024
WIDE_PORTS = 100
ACE_HEAVY = 1_000


@dataclass(frozen=True)
class AssetEntry:
    lo: int
    hi: int
    version: int
    system: str
    tier: str
    user_type: str | None


class AssetIndex:
    """Confirmed assets as sorted address intervals."""

    def __init__(self, assets: list[tuple[str, str, str, str | None]]) -> None:
        entries: list[AssetEntry] = []
        for network, system, tier, user_type in assets:
            if "-" in network:
                start_text, _, end_text = network.partition("-")
                start, end = ipaddress.ip_address(start_text), ipaddress.ip_address(end_text)
                entries.append(
                    AssetEntry(int(start), int(end), start.version, system, tier, user_type)
                )
            else:
                net = ipaddress.ip_network(network, strict=False)
                entries.append(
                    AssetEntry(
                        int(net.network_address),
                        int(net.broadcast_address),
                        net.version,
                        system,
                        tier,
                        user_type,
                    )
                )
        self.entries = sorted(entries, key=lambda e: (e.version, e.lo))

    def __len__(self) -> int:
        return len(self.entries)

    def touching(self, addresses: AddressSet) -> list[AssetEntry]:
        """Assets that intersect the address set (all assets for "any")."""
        if addresses.any:
            return list(self.entries)
        found = []
        for e in self.entries:
            intervals = addresses.v4 if e.version == 4 else addresses.v6
            if any(lo <= e.hi and e.lo <= hi for lo, hi in intervals):
                found.append(e)
        return found

    def unclassified(self, addresses: AddressSet) -> bool:
        """True if part of the (concrete) address set is covered by no asset."""
        if addresses.any:
            return False
        for version, intervals in ((4, addresses.v4), (6, addresses.v6)):
            blocks = [(e.lo, e.hi) for e in self.entries if e.version == version]
            for lo, hi in intervals:
                cursor = lo
                for b_lo, b_hi in sorted(blocks):
                    if b_hi < cursor or b_lo > hi:
                        continue
                    if b_lo > cursor:
                        return True
                    cursor = b_hi + 1
                    if cursor > hi:
                        break
                if cursor <= hi:
                    return True
        return False


@dataclass(frozen=True)
class RuleFacts:
    action: str
    enabled: bool
    src: AddressSet
    dst: AddressSet
    dst_ports_any: bool
    dst_port_count: int | None
    apps_any: bool
    ips_policy: str | None
    file_policy: str | None
    log_end: bool
    log_begin: bool
    hit_count: int | None
    dead: bool
    shadowed_by: str | None
    has_literals: bool
    ace_count: int


@dataclass
class ScoreResult:
    score: int | None
    reasons: list[dict[str, Any]] = field(default_factory=list)
    src_tiers: list[str] = field(default_factory=list)
    dst_tiers: list[str] = field(default_factory=list)


def score_rule(facts: RuleFacts, assets: AssetIndex) -> ScoreResult:
    src_assets = assets.touching(facts.src) if len(assets) else []
    dst_assets = assets.touching(facts.dst) if len(assets) else []
    src_tiers = sorted({a.tier for a in src_assets})
    dst_tiers = sorted({a.tier for a in dst_assets})
    if not facts.enabled or facts.action not in PERMIT_ACTIONS:
        return ScoreResult(None, src_tiers=src_tiers, dst_tiers=dst_tiers)

    reasons: list[dict[str, Any]] = []

    def deduct(code: str, points: int, **detail: Any) -> None:
        reasons.append({"code": code, "points": points, **detail})

    dst_size, src_size = facts.dst.size(), facts.src.size()
    if facts.dst.any:
        deduct("any_destination", 25)
    elif dst_size is not None and dst_size > BROAD_DESTINATION:
        deduct("broad_destination", 10, addresses=dst_size)
    if facts.src.any:
        deduct("any_source", 15)
    elif src_size is not None and src_size > BROAD_SOURCE:
        deduct("broad_source", 10, addresses=src_size)
    if facts.dst_ports_any and facts.apps_any:
        deduct("any_service", 15)
    elif facts.dst_port_count is not None and facts.dst_port_count > WIDE_PORTS:
        deduct("wide_ports", 5, ports=facts.dst_port_count)

    tiers = [t for t in dst_tiers if t in TIER_RANK]
    if len(tiers) > 1:
        deduct("multi_tier_destination", 20, tiers=tiers)
    if "GOLD" in tiers:
        if facts.src.any or (src_size is not None and src_size > GOLD_MANY_SOURCES):
            deduct("gold_many_sources", 15, addresses=src_size)
        if not facts.ips_policy:
            deduct("gold_without_ips", 10)
        if not facts.file_policy:
            deduct("gold_without_file_policy", 5)
    elif "SILVER" in tiers and not facts.ips_policy:
        deduct("silver_without_ips", 5)
    src_ranked = [TIER_RANK[t] for t in src_tiers if t in TIER_RANK]
    dst_ranked = [TIER_RANK[t] for t in tiers]
    if src_ranked and dst_ranked and max(dst_ranked) - min(src_ranked) >= 2:
        deduct(
            "tier_skip",
            30,
            source=min(src_tiers, key=lambda t: TIER_RANK.get(t, 9)),
            destination=max(tiers, key=TIER_RANK.__getitem__),
        )
    if facts.shadowed_by:
        deduct("shadowed", 20, by=facts.shadowed_by)
    if facts.dead:
        deduct("dead", 10, hits=facts.hit_count)
    if facts.has_literals:
        deduct("inline_literals", 5)
    if facts.ace_count > ACE_HEAVY:
        deduct("ace_heavy", 5, aces=facts.ace_count)
    if not facts.log_end and not facts.log_begin:
        deduct("no_logging", 5)
    if len(assets) and assets.unclassified(facts.dst):
        deduct("unclassified_destination", 0)
    score = max(0, 100 - sum(int(r["points"]) for r in reasons))
    return ScoreResult(score, reasons, src_tiers, dst_tiers)
