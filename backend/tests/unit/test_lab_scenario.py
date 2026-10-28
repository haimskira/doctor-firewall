"""The lab scenario is deterministic, complete and as messy as intended."""

from __future__ import annotations

from collections import Counter

from app.tools.lab_scenario import build


def test_scenario_shape() -> None:
    sc = build(seed=7, objects=10_000, rules=3_000)
    assert len(sc.objects) == 10_000
    assert len(sc.rules) == 3_000
    assert build(seed=7, objects=10_000, rules=3_000).rules[123].name == sc.rules[123].name
    names = [r.name for r in sc.rules]
    assert len(set(names)) == len(names)
    # Every reference resolves; groups only contain objects created before them.
    for o in sc.objects.values():
        for m in o.members:
            assert m in sc.objects
            assert sc.objects[m].depth < o.depth or sc.objects[m].resource != o.resource
    for r in sc.rules:
        assert all(n in sc.objects for n in r.src + r.dst + r.ports)
    patterns = Counter(r.pattern for r in sc.rules)
    for wanted in ("duplicate", "shadowed", "merge", "split", "tier_skip", "trust", "redundant"):
        assert patterns[wanted] > 20, wanted
    assert max(o.depth for o in sc.objects.values()) == 8
    assert any(r.name == "TEMP_ANY_ANY_DO_NOT_USE" for r in sc.rules)
    assert {a["tier"] for a in sc.assets} == {"CORE", "GOLD", "SILVER", "BRONZE", "USERS"}


def test_dry_run_scenario_has_four_policies_and_every_kind_of_mess() -> None:
    from app.tools.lab_scenario import build_policies

    sc = build_policies(seed=11, objects=8_000, rules=2_000)
    assert len(sc.policies) == 4
    assert all(len(rules) == 2_000 for rules in sc.policies.values())
    assert len(sc.objects) >= 8_000
    for rules in sc.policies.values():
        names = [r.name for r in rules]
        assert len(set(names)) == len(names)  # unique within the policy, as the FMC wants
        assert all(n in sc.objects for r in rules for n in r.src + r.dst + r.ports)
        assert all(n in sc.dynamic for r in rules for n in r.dst_dynamic)
        patterns = Counter(r.pattern for r in rules)
        for wanted in (
            "duplicate",
            "shadowed",
            "merge",
            "split",
            "wide_ports",
            "literal",
            "tier_skip",
            "trust",
            "redundant",
            "disabled",
            "gold_without_ips",
            "dynamic",
            "prefilter_blocked",
        ):
            assert patterns[wanted] > 0, wanted
    assert sc.dynamic
    # Servers declare their services: what port tightening needs.
    assert all(a.get("ports") for a in sc.assets if a["tier"] in ("GOLD", "SILVER"))
    # The classic scenario is unchanged by the extras.
    assert build(seed=7, objects=10_000, rules=3_000).rules[123].name == build().rules[123].name
