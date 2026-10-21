"""Executable plans, conflicts and batching under the deploy limit (pure logic)."""

from __future__ import annotations

from typing import Any

import pytest

from app.enforce.batching import Item, ItemTooLargeError, batch, conflicts, order
from app.enforce.plan import PlanBuilder, identity, touched

RULE = {"policy": "p1", "policy_kind": "access", "id": "r1", "name": "R1"}
OBJ = {"id": "o1", "type": "Network", "name": "NET_A"}


def _item(key: str, kind: str, plan: dict[str, Any], clusters: tuple[str, ...] = ("c1",)) -> Item:
    return Item(key=key, kind=kind, title=key, plan=plan, clusters=frozenset(clusters))


def _plan(build: Any) -> dict[str, Any]:
    pb = PlanBuilder()
    build(pb)
    return pb.build()


def test_plan_builder() -> None:
    ref_a = {"id": "a", "type": "Network", "name": "A"}
    ref_b = {"id": "b", "type": "Network", "name": "B"}
    # Unchanged fields produce no operation; a rename alone does.
    assert (
        _plan(lambda pb: pb.update_rule(RULE, {"dst_net": [ref_a]}, {"dst_net": [ref_a]}))["ops"]
        == []
    )
    plan = _plan(lambda pb: pb.update_rule(RULE, {"dst_net": [ref_a, ref_b]}, {"dst_net": [ref_a]}))
    assert plan["executable"] is True
    op = plan["ops"][0]
    assert op["op"] == "update_rule"
    assert op["expect"] == {"name": "R1", "fields": {"dst_net": ["o:a", "o:b"]}}
    assert op["set"] == {"dst_net": [ref_a]}
    nat = _plan(lambda pb: pb.delete_rule({**RULE, "policy_kind": "nat"}))
    assert nat["executable"] is False
    assert nat["blocked"] == ["unsupported_rule_kind:nat"]
    assert _plan(lambda pb: None)["executable"] is False  # nothing to do is not executable

    pb = PlanBuilder()
    new = pb.create_object("network_group", "GRP_GOLD", members=[ref_a])
    assert new == {"temp": "new:1", "type": "NetworkGroup", "name": "GRP_GOLD"}
    created = pb.create_rule(
        RULE, {"dst_net": [ref_a]}, insert_after="r1", name="R1_B", new={"dst_net": [new]}
    )
    assert created == "new:2"
    assert identity(new) == "t:new:1"
    assert identity({"literal": "10.0.0.1/32", "literal_kind": "address"}) == "l:10.0.0.1/32"
    pb.create_object("fqdn", "X", value="x.example")
    assert pb.build()["blocked"] == ["unsupported_object_kind:fqdn"]


def test_touched() -> None:
    plan = _plan(
        lambda pb: (
            pb.update_rule(RULE, {"src_net": []}, {"src_net": [OBJ]}),
            pb.delete_object({"id": "o9", "type": "Host", "name": "H"}),
        )
    )
    t = touched(plan)
    assert t["rules"] == {"p1/r1"}
    assert t["objects"] == {"o9"}
    assert t["deleted"] == {"o9"}
    assert t["referenced"] == {"o1"}


def test_conflicts() -> None:
    update_r1 = _plan(lambda pb: pb.update_rule(RULE, {}, {}, name="NEW"))
    delete_r1 = _plan(lambda pb: pb.delete_rule(RULE))
    rename_o1 = _plan(lambda pb: pb.rename_object(OBJ, "NET_B"))
    delete_o1 = _plan(lambda pb: pb.delete_object(OBJ))
    uses_o1 = _plan(
        lambda pb: pb.update_rule(
            {**RULE, "id": "r2", "name": "R2"}, {"dst_net": []}, {"dst_net": [OBJ]}
        )
    )
    other = _plan(lambda pb: pb.delete_rule({**RULE, "id": "r3", "name": "R3"}))
    assert [
        c.reason for c in conflicts([_item("a", "x", update_r1), _item("b", "x", delete_r1)])
    ] == ["same_rule"]
    assert [
        c.reason for c in conflicts([_item("a", "x", rename_o1), _item("b", "x", delete_o1)])
    ] == ["same_object"]
    assert [
        c.reason for c in conflicts([_item("a", "x", uses_o1), _item("b", "x", delete_o1)])
    ] == ["deletes_used"]
    assert (
        conflicts([_item("a", "x", update_r1), _item("b", "x", other), _item("c", "x", rename_o1)])
        == []
    )


def _ops(n: int, key: str) -> dict[str, Any]:
    pb = PlanBuilder()
    for i in range(n):
        pb.delete_rule({**RULE, "id": f"{key}-{i}", "name": f"{key}-{i}"})
    return pb.build()


def test_order_puts_creations_first_and_object_deletions_last() -> None:
    items = [
        _item("u", "remove_unused_object", _ops(1, "u")),
        _item("l", "literal_to_object", _ops(1, "l")),
        _item("s", "split_rule", _ops(1, "s")),
    ]
    assert [i.key for i in order(items)] == ["l", "s", "u"]


def test_batching_respects_the_limit_and_keeps_items_whole() -> None:
    limits = {"c1": 5, "c2": 3}

    def limit_of(clusters: set[str]) -> int:
        return min((limits[c] for c in clusters), default=100)

    items = [
        _item("a", "split_rule", _ops(3, "a"), ("c1",)),
        _item("b", "split_rule", _ops(2, "b"), ("c1",)),
        _item("c", "split_rule", _ops(2, "c"), ("c1",)),
        _item("d", "split_rule", _ops(1, "d"), ("c2",)),
    ]
    planned = batch(items, limit_of)
    assert [[i.key for i in b.items] for b in planned] == [["a", "b"], ["c", "d"]]
    assert [b.op_count for b in planned] == [5, 3]
    assert all(b.op_count <= b.limit for b in planned)
    # d touches c2: the second batch now covers c1 + c2, so its limit drops to c2's (3).
    assert planned[1].limit == 3
    assert planned[1].clusters == {"c1", "c2"}
    # With one more operation d no longer fits under the lowered limit: a third batch.
    items[3] = _item("d", "split_rule", _ops(2, "d"), ("c2",))
    assert [[i.key for i in b.items] for b in batch(items, limit_of)] == [["a", "b"], ["c"], ["d"]]
    with pytest.raises(ItemTooLargeError) as exc:
        batch([_item("big", "split_rule", _ops(4, "big"), ("c2",))], limit_of)
    assert exc.value.limit == 3
