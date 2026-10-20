"""Connectivity map building blocks: interval-indexed assets, node mapping, rule risk."""

from __future__ import annotations

import ipaddress
import random

from app.analysis.connectivity import ANY, UNCLASSIFIED, NodeMapper, edges_for, rule_risk, worst
from app.analysis.score import AssetIndex
from app.analysis.space import AddressSet


def _naive(index: AssetIndex, addresses: AddressSet) -> list[tuple[int, int, str]]:
    found = []
    for e in index.entries:
        intervals = addresses.v4 if e.version == 4 else addresses.v6
        if any(lo <= e.hi and e.lo <= hi for lo, hi in intervals):
            found.append((e.lo, e.hi, e.system))
    return sorted(found)


def test_touching_matches_the_naive_scan() -> None:
    rng = random.Random(7)  # noqa: S311 - deterministic test data
    assets = []
    for i in range(300):
        prefix = rng.choice([8, 12, 16, 20, 24, 28, 32])
        net = ipaddress.ip_network(
            f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.0/{prefix}", strict=False
        )
        assets.append((str(net), f"S{i}", rng.choice(["GOLD", "SILVER", "BRONZE"]), None))
    assets.append(("2001:db8::/32", "V6", "CORE", None))
    index = AssetIndex(list({a[0]: a for a in assets}.values()))
    for _ in range(300):
        prefix = rng.choice([8, 16, 24, 30, 32])
        net = ipaddress.ip_network(
            f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.0/{prefix}", strict=False
        )
        query = AddressSet.build([str(net), "2001:db8:1::/48"])
        got = sorted((e.lo, e.hi, e.system) for e in index.touching(query))
        assert got == _naive(index, query)
    assert len(index.touching(AddressSet(any=True))) == len(index.entries)


def test_rule_risk() -> None:
    assert rule_risk(["tier_skip"]) == "red"
    assert rule_risk(["dead", "no_logging"]) == "red"
    assert rule_risk(["any_source", "any_destination"]) == "red"
    assert rule_risk(["any_source"]) == "yellow"
    assert rule_risk(["gold_without_ips"]) == "yellow"
    assert rule_risk(["no_logging", "inline_literals"]) == "green"
    assert rule_risk([]) == "green"
    assert worst("green", "red") == "red"
    assert worst("yellow", "green") == "yellow"


def test_nodes_and_edges() -> None:
    index = AssetIndex(
        [
            ("10.20.5.0/24", "SQL-FIN", "GOLD", None),
            ("10.100.10.0/24", "FIN-USERS", "USERS", "FIN"),
        ]
    )
    mapper = NodeMapper(index)
    assert mapper.nodes(AddressSet(any=True)) == (ANY,)
    assert mapper.nodes(AddressSet.build(["10.20.5.7/32"])) == ("GOLD|SQL-FIN",)
    assert mapper.nodes(AddressSet.build(["10.20.0.0/16"])) == ("GOLD|SQL-FIN", UNCLASSIFIED)
    assert mapper.nodes(AddressSet.build([], ["fqdn:x"])) == (UNCLASSIFIED,)
    assert mapper.nodes(AddressSet.build(["192.0.2.1/32"])) == (UNCLASSIFIED,)
    edges = edges_for(
        mapper, AddressSet.build(["10.100.10.0/24"]), AddressSet.build(["10.20.5.0/24"]), "green"
    )
    assert edges == [{"src": "USERS|FIN-USERS", "dst": "GOLD|SQL-FIN", "risk": "green"}]
    empty = NodeMapper(AssetIndex([]))
    assert empty.nodes(AddressSet.build(["10.0.0.0/8"])) == (UNCLASSIFIED,)
