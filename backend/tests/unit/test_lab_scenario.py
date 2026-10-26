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
