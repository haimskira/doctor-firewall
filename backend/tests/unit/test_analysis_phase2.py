"""Phase-2 analysis algorithms: match spaces, shadowing, expansion, scoring (pure)."""

from __future__ import annotations

import random
from typing import Any

import pytest

from app.analysis.expand import Leaves, Resolver, RuleSpace, ace_estimate, build_space
from app.analysis.score import AssetIndex, RuleFacts, score_rule
from app.analysis.shadow import analyse_order, analyse_order_naive
from app.analysis.space import AddressSet, MatchSpace, PortSet, TokenSet

# ------------------------------------------------------------------ address sets


def test_address_containment_merges_adjacent_blocks() -> None:
    whole = AddressSet.build(["10.0.0.0/24"])
    halves = AddressSet.build(["10.0.0.0/25", "10.0.0.128/25"])
    assert whole.covers(halves)
    assert halves.covers(whole)  # merged intervals: same space
    assert not AddressSet.build(["10.0.0.0/25"]).covers(whole)
    assert AddressSet.build(["10.0.0.0/8"]).covers(AddressSet.build(["10.1.2.3/32"]))
    assert AddressSet.build(["10.0.0.0-10.0.0.255"]).covers(whole)


def test_any_and_versions() -> None:
    anyset = AddressSet(any=True)
    v4 = AddressSet.build(["10.0.0.0/8"])
    v6 = AddressSet.build(["fd00::/8"])
    assert anyset.covers(v4)
    assert not v4.covers(anyset)
    assert not v4.covers(v6)
    assert not v4.intersects(v6)
    assert anyset.size() is None
    assert v4.size() == 2**24


def test_opaque_tokens_are_conservative() -> None:
    fqdn = AddressSet.build([], ["fqdn:updates.example"])
    big = AddressSet.build(["0.0.0.0/0"])
    assert not big.covers(fqdn)  # cannot prove the FQDN resolves inside
    assert fqdn.covers(fqdn)
    assert not big.intersects(fqdn)


def test_intersection() -> None:
    a = AddressSet.build(["10.0.0.0/24"])
    assert a.intersects(AddressSet.build(["10.0.0.200/32"]))
    assert not a.intersects(AddressSet.build(["10.0.1.0/24"]))


# ------------------------------------------------------------------ ports


def test_ports_and_protocols() -> None:
    web = PortSet.build(["TCP/80", "TCP/443"])
    assert PortSet.build(["TCP/0-65535"]).covers(web)
    assert PortSet.build(["TCP/1-1024"]).covers(web)
    assert not PortSet.build(["UDP/1-1024"]).covers(web)
    assert PortSet.build(["ALL/any"]).any
    assert PortSet.build(["ALL/any", "ICMP/8"]).covers(PortSet.build(["ICMP/8"]))
    assert not PortSet.build(["TCP/any"]).covers(PortSet.build(["ICMP/8"]))
    assert not web.covers(PortSet(any=True))
    assert web.intersects(PortSet.build(["TCP/443-500"]))
    assert not web.intersects(PortSet.build(["UDP/443"]))
    assert web.port_count() == 2


def test_tokens() -> None:
    zones = TokenSet.build(["z1", "z2"])
    assert zones.covers(TokenSet.build(["z1"]))
    assert not zones.covers(TokenSet(any=True))
    assert TokenSet.build([]).any


# ------------------------------------------------------------------ resolver & spaces


def _resolver() -> Resolver:
    objects: dict[str, tuple[str, str | None]] = {
        "h1": ("host", "10.0.0.1/32"),
        "n1": ("network", "10.0.0.0/24"),
        "f1": ("fqdn", "updates.example"),
        "stub": ("host", None),
        "g1": ("network_group", None),
        "g2": ("network_group", None),
        "loopA": ("network_group", None),
        "loopB": ("network_group", None),
        "p443": ("port", "TCP/443"),
        "pg": ("port_group", None),
        "z1": ("zone", None),
    }
    members: dict[str, list[tuple[str | None, str | None, str | None]]] = {
        "g1": [("h1", None, None), ("n1", None, None), (None, "192.168.1.0/24", "address")],
        "g2": [("g1", None, None), ("h1", None, None), ("f1", None, None)],
        "loopA": [("loopB", None, None), ("h1", None, None)],
        "loopB": [("loopA", None, None), ("stub", None, None)],
        "pg": [("p443", None, None), (None, "TCP/8080", "port")],
    }
    return Resolver(objects, members)


def test_resolver_flattens_groups_and_survives_cycles() -> None:
    r = _resolver()
    g2 = r.leaves("g2")
    assert g2.addresses == {"10.0.0.1/32", "10.0.0.0/24", "192.168.1.0/24"}
    assert g2.address_tokens == {"fqdn:updates.example"}
    loop = r.leaves("loopA")
    assert loop.addresses == {"10.0.0.1/32"}
    assert loop.address_tokens == {"stub"}
    assert r.leaves("pg").ports == {"TCP/443", "TCP/8080"}
    assert r.leaves("z1").tokens == {"z1"}
    assert r.leaves("unknown-id").tokens == {"unknown-id"}


def test_ace_estimate_is_a_product_of_leaf_counts() -> None:
    r = _resolver()
    fields = {
        "src_net": r.leaves("g1"),
        "dst_net": r.leaves("n1"),
        "dst_port": r.leaves("pg"),
        "src_zone": Leaves(tokens={"z1", "z2"}),
    }
    assert ace_estimate(fields) == 2 * 3 * 1 * 2  # zones x sources x destinations x ports
    assert ace_estimate({}) == 1


def _rule(index: int, action: str = "ALLOW", enabled: bool = True, **fields: Leaves) -> RuleSpace:
    return RuleSpace(
        rule_id=index,
        fmc_id=f"r{index}",
        policy_fmc_id="p",
        rule_index=index,
        section="Default",
        name=f"R{index}",
        enabled=enabled,
        action=action,
        hit_count=None,
        space=build_space(fields),
        ace_count=ace_estimate(fields),
        leaf_counts={},
    )


def _addr(*values: str) -> Leaves:
    return Leaves(addresses=set(values))


def _ports(*values: str) -> Leaves:
    return Leaves(ports=set(values))


# ------------------------------------------------------------------ shadowing


def test_shadowed_by_broader_earlier_rule() -> None:
    rules = [
        _rule(1, dst_net=_addr("10.20.0.0/16"), dst_port=_ports("TCP/1-65535")),
        _rule(2, dst_net=_addr("10.20.5.0/24"), dst_port=_ports("TCP/1433")),
        _rule(3, dst_net=_addr("10.30.0.0/16")),
    ]
    shadows, _ = analyse_order(rules)
    assert [(s.rule.rule_index, s.by.rule_index, s.conflict) for s in shadows] == [(2, 1, False)]


def test_conflicting_shadow_and_overlap() -> None:
    rules = [
        _rule(1, action="BLOCK", src_net=_addr("10.40.0.0/16")),
        _rule(2, src_net=_addr("10.40.1.0/24"), dst_net=_addr("10.20.5.0/24")),
        _rule(3, src_net=_addr("10.0.0.0/8"), dst_net=_addr("10.20.5.0/24")),
    ]
    shadows, overlaps = analyse_order(rules)
    assert [(s.rule.rule_index, s.conflict) for s in shadows] == [(2, True)]
    assert [(o.rule.rule_index, o.with_rule.rule_index) for o in overlaps] == [(3, 1)]


def test_monitor_and_disabled_rules_never_shadow() -> None:
    rules = [
        _rule(1, action="MONITOR"),
        _rule(2, enabled=False),
        _rule(3, dst_net=_addr("10.0.0.1/32")),
    ]
    shadows, _ = analyse_order(rules)
    assert shadows == []
    shadows, _ = analyse_order([_rule(1), _rule(2, enabled=False)])
    assert shadows == []  # a disabled rule is not reported as shadowed


def test_any_any_shadows_everything_after_it() -> None:
    rules = [_rule(1), _rule(2, dst_net=_addr("10.0.0.0/8")), _rule(3, action="BLOCK")]
    shadows, _ = analyse_order(rules)
    assert [(s.rule.rule_index, s.conflict) for s in shadows] == [(2, False), (3, True)]


def test_zones_and_applications_must_be_covered_too() -> None:
    rules = [
        _rule(1, src_zone=Leaves(tokens={"inside"}), app=Leaves(tokens={"http"})),
        _rule(2, src_zone=Leaves(tokens={"inside", "dmz"}), app=Leaves(tokens={"http"})),
        _rule(
            3,
            src_zone=Leaves(tokens={"inside"}),
            app=Leaves(tokens={"http"}),
            dst_net=_addr("10.0.0.0/8"),
        ),
    ]
    shadows, _ = analyse_order(rules)
    assert [s.rule.rule_index for s in shadows] == [3]


# ------------------------------------------------------------------ scoring


ASSETS = AssetIndex(
    [
        ("10.20.5.0/24", "SQL-FIN", "GOLD", None),
        ("10.30.0.0/16", "APPS", "SILVER", None),
        ("10.40.0.0/16", "DEV", "BRONZE", None),
        ("10.0.0.53/32", "DNS", "CORE", None),
        ("10.100.10.0/24", "FIN-USERS", "USERS", "FIN"),
    ]
)


def _facts(**overrides: Any) -> RuleFacts:
    base: dict[str, Any] = {
        "action": "ALLOW",
        "enabled": True,
        "src": AddressSet.build(["10.100.10.0/24"]),
        "dst": AddressSet.build(["10.20.5.10/32"]),
        "dst_ports_any": False,
        "dst_port_count": 1,
        "apps_any": True,
        "ips_policy": "Max",
        "file_policy": "Malware",
        "log_end": True,
        "log_begin": False,
        "hit_count": 10,
        "dead": False,
        "shadowed_by": None,
        "has_literals": False,
        "ace_count": 1,
    }
    base.update(overrides)
    return RuleFacts(**base)


def _codes(result: Any) -> set[str]:
    return {r["code"] for r in result.reasons}


def test_doctrine_compliant_gold_rule_scores_100() -> None:
    result = score_rule(_facts(), ASSETS)
    assert result.score == 100
    assert result.dst_tiers == ["GOLD"]
    assert result.src_tiers == ["USERS"]


def test_any_any_any_is_worst() -> None:
    result = score_rule(
        _facts(
            src=AddressSet(any=True),
            dst=AddressSet(any=True),
            dst_ports_any=True,
            dst_port_count=None,
            ips_policy=None,
            file_policy=None,
            log_end=False,
        ),
        ASSETS,
    )
    assert {
        "any_destination",
        "any_source",
        "any_service",
        "multi_tier_destination",
        "gold_many_sources",
        "gold_without_ips",
        "no_logging",
    } <= _codes(result)
    assert result.score == 0


def test_bronze_to_gold_is_a_tier_skip() -> None:
    result = score_rule(_facts(src=AddressSet.build(["10.40.1.0/24"])), ASSETS)
    assert "tier_skip" in _codes(result)
    assert result.score == 70


def test_each_deduction_is_explained() -> None:
    result = score_rule(
        _facts(
            ips_policy=None,
            dead=True,
            shadowed_by="r1",
            has_literals=True,
            ace_count=5000,
            dst_port_count=2000,
        ),
        ASSETS,
    )
    assert {
        "gold_without_ips",
        "dead",
        "shadowed",
        "inline_literals",
        "ace_heavy",
        "wide_ports",
    } <= _codes(result)
    assert result.score == 100 - sum(int(r["points"]) for r in result.reasons)
    assert all("points" in r and "code" in r for r in result.reasons)


def test_unscored_rules_and_unclassified_destinations() -> None:
    assert score_rule(_facts(action="BLOCK"), ASSETS).score is None
    assert score_rule(_facts(enabled=False), ASSETS).score is None
    result = score_rule(_facts(dst=AddressSet.build(["172.16.0.0/24"])), ASSETS)
    assert "unclassified_destination" in _codes(result)
    assert result.score == 100  # unclassified is informational (0 points)


def test_without_assets_no_tier_reasons() -> None:
    result = score_rule(_facts(src=AddressSet.build(["10.40.1.0/24"])), AssetIndex([]))
    assert result.dst_tiers == []
    assert result.score == 100


@pytest.mark.parametrize(
    ("dst", "expected"),
    [(["10.20.5.0/25"], False), (["10.20.5.0/23"], True), (["10.0.0.53/32"], False)],
)
def test_unclassified_detection(dst: list[str], expected: bool) -> None:
    assert ASSETS.unclassified(AddressSet.build(dst)) is expected


def test_match_space_defaults_to_any() -> None:
    space = MatchSpace()
    assert space.covers(build_space({"dst_net": _addr("10.0.0.0/8")}))


# ------------------------------------------------------------------ indexed vs naive


def _random_rules(rng: random.Random, n: int) -> list[RuleSpace]:
    nets = [
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
        "10.1.2.3/32",
        "10.2.0.0/16",
        "10.1.2.0-10.1.3.255",
        "192.168.0.0/16",
        "192.168.5.0/24",
        "fd00::/8",
        "fd00::1/128",
    ]
    tokens = ["fqdn:a.example", "fqdn:b.example", "stub1"]
    ports = ["TCP/80", "TCP/443", "TCP/1-1024", "UDP/53", "TCP/any", "ICMP/8"]

    def addresses() -> Leaves | None:
        roll = rng.random()
        if roll < 0.15:
            return None  # any
        leaves = Leaves(addresses=set(rng.sample(nets, rng.randint(1, 2))))
        if roll > 0.9:
            leaves.address_tokens.add(rng.choice(tokens))
        return leaves

    rules = []
    for i in range(n):
        fields: dict[str, Leaves] = {}
        for name in ("src_net", "dst_net"):
            if (value := addresses()) is not None:
                fields[name] = value
        if rng.random() < 0.6:
            fields["dst_port"] = Leaves(ports=set(rng.sample(ports, rng.randint(1, 2))))
        if rng.random() < 0.2:
            fields["src_zone"] = Leaves(tokens={rng.choice(["inside", "dmz"])})
        rules.append(
            _rule(
                i,
                action=rng.choice(["ALLOW", "ALLOW", "BLOCK", "MONITOR", "TRUST"]),
                enabled=rng.random() > 0.05,
                **fields,
            )
        )
    return rules


@pytest.mark.parametrize("seed", range(25))
def test_indexed_analysis_matches_naive(seed: int) -> None:
    rules = _random_rules(random.Random(seed), 120)  # noqa: S311 - deterministic test data
    fast_s, fast_o = analyse_order(rules)
    slow_s, slow_o = analyse_order_naive(rules)
    assert [(s.rule.rule_id, s.by.rule_id, s.conflict) for s in fast_s] == [
        (s.rule.rule_id, s.by.rule_id, s.conflict) for s in slow_s
    ]
    assert [(o.rule.rule_id, o.with_rule.rule_id) for o in fast_o] == [
        (o.rule.rule_id, o.with_rule.rule_id) for o in slow_o
    ]
