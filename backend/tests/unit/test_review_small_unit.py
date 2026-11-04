"""Shadow analysis: the destination index keeps results; the overlap scan is capped."""

from __future__ import annotations

import random
import time
from typing import Any

import pytest

from app.analysis import shadow
from app.analysis.expand import Leaves, RuleSpace, ace_estimate, build_space
from app.analysis.shadow import analyse_order, analyse_order_naive


def _rule(index: int, action: str, **fields: Leaves) -> RuleSpace:
    return RuleSpace(
        rule_id=index,
        fmc_id=f"r{index}",
        policy_fmc_id="p",
        rule_index=index,
        section="Default",
        name=f"R{index}",
        enabled=True,
        action=action,
        hit_count=None,
        space=build_space(fields),
        ace_count=ace_estimate(fields),
        leaf_counts={},
    )


def _random_rules(rng: random.Random, n: int) -> list[RuleSpace]:
    v4 = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "192.168.0.0/16", "172.16.4.0/24"]
    v6 = ["fd00::/8", "fd00:1::/32", "fd00:1::5/128", "2001:db8::/32"]
    tokens = ["fqdn:a.example", "fqdn:b.example"]
    rules = []
    for i in range(n):
        fields: dict[str, Leaves] = {}
        for name in ("src_net", "dst_net"):
            roll = rng.random()
            if roll < 0.2:
                continue  # any
            leaves = Leaves(addresses=set())
            if roll < 0.55:
                leaves.addresses.add(rng.choice(v4))
            elif roll < 0.8:
                leaves.addresses.add(rng.choice(v6))
            elif roll < 0.9:
                leaves.address_tokens.add(rng.choice(tokens))
            else:
                leaves.addresses.update((rng.choice(v4), rng.choice(v6)))
            fields[name] = leaves
        if rng.random() < 0.5:
            fields["dst_port"] = Leaves(ports={rng.choice(["TCP/80", "TCP/443", "UDP/53"])})
        rules.append(_rule(i, rng.choice(["ALLOW", "BLOCK", "ALLOW", "MONITOR"]), **fields))
    return rules


def _shape(result: tuple[list[shadow.Shadow], list[shadow.Overlap]]) -> tuple[Any, Any]:
    shadows, overlaps = result
    return (
        [(s.rule.rule_id, s.by.rule_id, s.conflict) for s in shadows],
        [(o.rule.rule_id, o.with_rule.rule_id) for o in overlaps],
    )


@pytest.mark.parametrize("seed", range(30))
@pytest.mark.parametrize("size", [150, 500])  # 500: more than MAX_ANY_DESTINATIONS "any" rules
def test_non_ipv4_destinations_match_the_naive_scan(seed: int, size: int) -> None:
    rules = _random_rules(random.Random(seed), size)  # noqa: S311 - deterministic test data
    assert _shape(analyse_order(rules)) == _shape(analyse_order_naive(rules))


def test_the_overlap_scan_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    # Earlier deny rules with disjoint IPv6 destinations: the last rule meets only the first
    # of them; with a small cap the scan stops before reaching it.
    rules = [
        _rule(
            i,
            "BLOCK",
            src_net=Leaves(addresses={"10.9.0.0/24"}),
            dst_net=Leaves(addresses={f"fd00:{i:x}::/48"}),
        )
        for i in range(1, 30)
    ]
    rules.append(_rule(101, "ALLOW", dst_net=Leaves(addresses={"fd00:1::/48"})))
    rules.append(_rule(102, "ALLOW", dst_net=Leaves(addresses={"fd00:1d::/48"})))
    open_scan = [o.with_rule.rule_id for o in analyse_order(rules)[1] if o.rule.rule_id == 102]
    assert open_scan == [29]
    monkeypatch.setattr(shadow, "MAX_OVERLAP_SCAN", 5)
    capped = [o for o in analyse_order(rules)[1] if o.rule.rule_id == 102]
    assert capped == []


def test_twenty_thousand_rules_with_wide_destinations_finish_quickly() -> None:
    rng = random.Random(7)  # noqa: S311 - deterministic test data
    rules = []
    for i in range(20000):
        kind = i % 4
        src = Leaves(addresses={f"10.{rng.randrange(256)}.{rng.randrange(256)}.0/24"})
        if kind == 0:
            rules.append(_rule(i, "ALLOW", src_net=src))  # any destination
        elif kind == 1:
            dst = Leaves(addresses={f"fd00:{rng.randrange(65535):x}::/48"})
            rules.append(_rule(i, "BLOCK", src_net=src, dst_net=dst))
        elif kind == 2:
            dst = Leaves(address_tokens={f"fqdn:h{rng.randrange(500)}.example"})
            rules.append(_rule(i, "ALLOW", src_net=src, dst_net=dst))
        else:
            dst = Leaves(addresses={f"172.16.{rng.randrange(256)}.0/24"})
            rules.append(_rule(i, "BLOCK", src_net=src, dst_net=dst))
    start = time.monotonic()
    analyse_order(rules)
    assert time.monotonic() - start < 30
