"""Attack surface engine: hops, pivots on address sets, ranking, blast radius."""

from __future__ import annotations

from typing import Any

from app.analysis.attack import Hop, describe, search
from app.analysis.score import AssetIndex
from app.analysis.space import AddressSet

ASSETS = AssetIndex(
    [
        ("10.3.0.0/24", "A", "GOLD", None),
        ("10.2.0.0/24", "B", "SILVER", None),
        ("10.1.0.0/24", "C", "USERS", "office"),
        ("10.4.0.0/24", "D", "BRONZE", None),
    ]
)
LABELS = {"GOLD|A": "A", "SILVER|B": "B", "USERS|C": "C", "BRONZE|D": "D"}


def hop(
    rule: str,
    src: list[str] | None,
    dst: list[str] | None,
    services: tuple[str, ...] = ("tcp/443",),
    *,
    inspected: bool = True,
    risk: str = "green",
) -> Hop:
    return Hop(
        rule_id=hash(rule) & 0xFFFF,
        fmc_id=rule,
        name=rule,
        index=int(rule[1:]) if rule[1:].isdigit() else 0,
        policy_fmc_id="p1",
        policy_name="ACP",
        action="ALLOW",
        src=AddressSet(any=True) if src is None else AddressSet.build(src),
        dst=AddressSet(any=True) if dst is None else AddressSet.build(dst),
        services=services,
        apps=(),
        inspected=inspected,
        partial=False,
        risk=risk,
        hits=None,
    )


# B's lower half may reach A; C reaches only B's upper half; D reaches all of B.
HOPS = [
    hop("r1", ["10.2.0.0/25"], ["10.3.0.0/24"], ("tcp/1433",)),
    hop("r2", ["10.1.0.0/24"], ["10.2.0.128/25"]),
    hop("r3", ["10.4.0.0/24"], ["10.2.0.0/24"], ("tcp/22",), inspected=False),
    hop("r4", ["10.3.0.0/24"], ["10.3.0.0/24"], ("any",)),  # inside A: not a way in
]
A = AddressSet.build(["10.3.0.0/24"])


def _flows(result: dict[str, Any]) -> list[list[str]]:
    return [[s["nodes"][0] for s in p["steps"]] for p in result["paths"]]


def test_pivots_follow_addresses_not_system_names() -> None:
    result = describe(search(HOPS, A, "to", 3), ASSETS, LABELS)
    flows = _flows(result)
    assert ["SILVER|B", "GOLD|A"] in flows
    assert ["BRONZE|D", "SILVER|B", "GOLD|A"] in flows
    # C reaches only the half of B that may not reach A: no path from C.
    assert not any("USERS|C" in f for f in flows)
    depth = {n["id"]: n["depth"] for n in result["nodes"]}
    assert depth == {"GOLD|A": 0, "SILVER|B": 1, "BRONZE|D": 2}
    pivot = next(p for p in result["paths"] if len(p["steps"]) == 3)
    assert [h["services"] for h in pivot["hops"]] == [["tcp/22"], ["tcp/1433"]]
    assert {"pivot", "uninspected"} <= set(pivot["reasons"])
    assert "tier_skip" not in pivot["reasons"]  # BRONZE -> SILVER -> GOLD: one tier a hop
    assert result["summary"]["shortest"] == 1
    assert result["summary"]["anywhere"] is False
    assert result["summary"]["services"] == ["tcp/1433"]
    assert result["origin"]["networks"] == ["10.3.0.0/24"]


def test_anywhere_entry_ranks_first_and_depth_is_capped() -> None:
    hops = [*HOPS, hop("r5", None, ["10.4.0.0/24"], ("any",), risk="red")]
    shallow = describe(search(hops, A, "to", 2), ASSETS, LABELS)
    assert ["ANY", "BRONZE|D", "SILVER|B", "GOLD|A"] not in _flows(shallow)
    deep = describe(search(hops, A, "to", 3), ASSETS, LABELS)
    top = deep["paths"][0]
    assert [s["nodes"][0] for s in top["steps"]] == ["ANY", "BRONZE|D", "SILVER|B", "GOLD|A"]
    assert "anywhere" in top["reasons"]
    assert deep["summary"]["anywhere"] is True
    any_edge = next(e for e in deep["edges"] if e["src"] == "ANY")
    assert any_edge["risk"] == "red"
    assert any_edge["rules"][0]["name"] == "r5"


def test_bronze_straight_to_gold_is_a_tier_skip() -> None:
    hops = [*HOPS, hop("r6", ["10.4.0.0/24"], ["10.3.0.0/24"], ("tcp/1433",))]
    result = describe(search(hops, A, "to", 1), ASSETS, LABELS)
    direct = next(p for p in result["paths"] if p["steps"][0]["nodes"] == ["BRONZE|D"])
    assert {"direct", "tier_skip"} <= set(direct["reasons"])
    assert direct is result["paths"][0]  # ranked above SILVER -> GOLD


def test_blast_radius_goes_with_the_flow() -> None:
    from_c = describe(search(HOPS, AddressSet.build(["10.1.0.0/24"]), "from", 3), ASSETS, LABELS)
    assert _flows(from_c) == [["USERS|C", "SILVER|B"]]  # B's upper half cannot go on to A
    from_d = describe(search(HOPS, AddressSet.build(["10.4.0.0/24"]), "from", 3), ASSETS, LABELS)
    assert ["BRONZE|D", "SILVER|B", "GOLD|A"] in _flows(from_d)
    assert {n["id"]: n["depth"] for n in from_d["nodes"]}["GOLD|A"] == 2


def test_nothing_reaches_an_isolated_target() -> None:
    lonely = AddressSet.build(["192.0.2.0/24"])
    result = describe(search(HOPS, lonely, "to", 4), ASSETS, LABELS)
    assert result["paths"] == []
    assert result["summary"]["paths"] == 0
    assert result["summary"]["shortest"] is None


def test_set_operations() -> None:
    a = AddressSet.build(["10.0.0.0/24", "10.0.2.0/24"])
    b = AddressSet.build(["10.0.0.128/25", "10.0.1.0/24", "10.0.2.0/30"])
    both = a.intersection(b)
    assert both == AddressSet.build(["10.0.0.128/25", "10.0.2.0/30"])
    assert AddressSet(any=True).intersection(a) == a
    assert a.intersection(AddressSet.build(["192.0.2.1/32"])).empty
    assert not AddressSet(any=True).empty
