from __future__ import annotations

from collections import Counter

import pytest

from app.analysis.graph import (
    GroupGraph,
    combine,
    depths,
    introduced_duplicates,
    leaf_counts,
    strongly_connected,
)
from app.collector.signature import rule_signature
from app.fmc import normalize
from app.fmc.records import Ref, RuleField

# ------------------------------------------------------------------ normalize


@pytest.mark.parametrize(
    ("func", "value", "expected"),
    [
        (normalize.host, " 10.0.0.1 ", "10.0.0.1/32"),
        (normalize.host, "fd00::1", "fd00::1/128"),
        (normalize.network, "10.20.5.77/24", "10.20.5.0/24"),
        (normalize.address, "10.0.0.1", "10.0.0.1/32"),
        (normalize.address, "10.0.0.0/8", "10.0.0.0/8"),
        (normalize.ip_range, "10.0.0.1-10.0.0.9", "10.0.0.1-10.0.0.9"),
    ],
)
def test_addresses(func: object, value: str, expected: str) -> None:
    assert func(value) == expected  # type: ignore[operator]


@pytest.mark.parametrize(
    ("func", "value"),
    [
        (normalize.host, "10.0.0.256"),
        (normalize.network, "nope"),
        (normalize.ip_range, "10.0.0.9-10.0.0.1"),
        (normalize.ip_range, "10.0.0.1"),
        (normalize.ip_range, "10.0.0.1-fd00::1"),
    ],
)
def test_invalid_addresses(func: object, value: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - any ValueError subtype is correct
        func(value)  # type: ignore[operator]


@pytest.mark.parametrize(
    ("proto", "port", "expected"),
    [
        ("TCP", "443", "TCP/443"),
        ("6", "443", "TCP/443"),
        ("17", "1000-2000", "UDP/1000-2000"),
        ("tcp", None, "TCP/any"),
        (None, None, "ALL/any"),
        ("TCP", "80-80", "TCP/80"),
    ],
)
def test_ports(proto: str | None, port: str | None, expected: str) -> None:
    assert normalize.port_spec(proto, port) == expected


@pytest.mark.parametrize(("proto", "port"), [("TCP", "70000"), ("TCP", "90-80"), ("BOGUS", "1")])
def test_invalid_ports(proto: str, port: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        normalize.port_spec(proto, port)


def test_prefix_length_and_text() -> None:
    assert normalize.prefix_length("255.255.255.0") == 24
    assert normalize.prefix_length("64", version=6) == 64
    with pytest.raises(ValueError):  # noqa: PT011
        normalize.prefix_length("40")
    assert normalize.text("  x  ") == "x"
    assert normalize.text(None) == ""
    assert len(normalize.text("y" * 5000)) == normalize.MAX_TEXT


# ------------------------------------------------------------------ signature


def test_signature_ignores_order_and_names_but_not_action() -> None:
    a = (RuleField.SRC_NET, Ref(object_id="o1", name="A"))
    b = (RuleField.SRC_NET, Ref(object_id="o2", name="B"))
    c = (RuleField.DST_PORT, Ref(literal="TCP/443", literal_kind="port"))
    assert rule_signature("ALLOW", (a, b, c)) == rule_signature("ALLOW", (c, b, a))
    renamed = (RuleField.SRC_NET, Ref(object_id="o1", name="renamed"))
    assert rule_signature("ALLOW", (a,)) == rule_signature("ALLOW", (renamed,))
    assert rule_signature("ALLOW", (a,)) != rule_signature("BLOCK", (a,))
    moved = (RuleField.DST_NET, Ref(object_id="o1"))
    assert rule_signature("ALLOW", (a,)) != rule_signature("ALLOW", (moved,))
    assert rule_signature("ALLOW", ()) == rule_signature("ALLOW", ())


# ------------------------------------------------------------------ graph


def _graph(**members: list[str]) -> GroupGraph:
    return GroupGraph(members=dict(members))


def test_cycles_found_including_self_loops() -> None:
    g = _graph(A=["B", "h1"], B=["A"], C=["C"], D=["h2"], E=["D"])
    assert sorted(strongly_connected(g)) == [["A", "B"], ["C"]]
    assert strongly_connected(_graph(A=["B"], B=["h"])) == []


def test_long_cycle_and_deep_chain_are_iterative() -> None:
    n = 5000  # would overflow a recursive implementation
    chain = {f"G{i}": [f"G{i + 1}"] for i in range(n)}
    chain[f"G{n}"] = ["leaf"]
    g = GroupGraph(members=chain)
    assert strongly_connected(g) == []
    assert depths(g, set())["G0"] == n + 1
    ring = {f"R{i}": [f"R{(i + 1) % n}"] for i in range(n)}
    assert len(strongly_connected(GroupGraph(members=ring))[0]) == n


def test_depths_skip_cyclic_groups() -> None:
    g = _graph(TOP=["MID", "h1"], MID=["LEAF"], LEAF=["h2"], X=["Y"], Y=["X"])
    d = depths(g, {"X", "Y"})
    assert d == {"TOP": 3, "MID": 2, "LEAF": 1}


def test_leaf_counts_and_introduced_duplicates() -> None:
    # TOP contains GOLD and also h1 directly; GOLD contains h1 -> h1 reached twice at TOP.
    g = _graph(TOP=["GOLD", "h1", "lit:10.0.0.0/8"], GOLD=["h1", "h2"], OUTER=["TOP"])
    counts = leaf_counts(g, set())
    assert counts["TOP"] == Counter({"h1": 2, "h2": 1, "lit:10.0.0.0/8": 1})
    top_dups = introduced_duplicates(counts["TOP"], [counts["GOLD"]])
    assert top_dups == {"h1": 2}
    # OUTER inherits the duplicate from TOP; it must not be reported again.
    assert introduced_duplicates(counts["OUTER"], [counts["TOP"]]) == {}


def test_combine_rule_field() -> None:
    g = _graph(GOLD=["h1", "h2"])
    counts = leaf_counts(g, set())
    total, parts = combine(["GOLD", "h1", "lit:1.1.1.1/32"], g, counts)
    assert total == Counter({"h1": 2, "h2": 1, "lit:1.1.1.1/32": 1})
    assert introduced_duplicates(total, parts) == {"h1": 2}
    # Cyclic groups have no leaf set and are skipped rather than looping.
    cyc = _graph(A=["B"], B=["A"])
    total, parts = combine(["A"], cyc, leaf_counts(cyc, {"A", "B"}))
    assert total == Counter()
    assert parts == []
