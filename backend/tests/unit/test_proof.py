"""Traffic proof: behaviour-preserving plans show no difference; real changes are caught."""

from __future__ import annotations

from typing import Any

from app.enforce.proof import Model, PolicyModel, RuleModel, apply_plan, compare


def rule(key: str, action: str = "ALLOW", **refs: list[str]) -> RuleModel:
    return RuleModel(
        key=key,
        name=key.upper(),
        enabled=True,
        action=action,
        ips=None,
        file=None,
        refs={f: [(o, None, None) for o in objs] for f, objs in refs.items()},
    )


def model(rules: list[RuleModel]) -> Model:
    return Model(
        objects={
            "h1": ("host", "10.0.0.1/32"),
            "h1copy": ("host", "10.0.0.1/32"),
            "n1": ("network", "10.1.0.0/24"),
            "n2": ("network", "10.2.0.0/24"),
            "users_a": ("network", "10.50.0.0/24"),
            "users_b": ("network", "10.51.0.0/24"),
            "g1": ("network_group", None),
            "https": ("port", "TCP/443"),
            "ssh": ("port", "TCP/22"),
        },
        members={"g1": [("n1", None, None)]},
        policies={"p1": PolicyModel("p1", "ACP", "access", "BLOCK", rules)},
    )


BASE = [
    rule("r1", dst_net=["g1"], dst_port=["https"]),
    rule("r2", "BLOCK", dst_net=["n1"]),
    rule("r3", dst_net=["h1copy"], dst_port=["ssh"]),
]
RULE = {"policy": "p1", "policy_kind": "access"}


def proof(rules: list[RuleModel], ops: list[dict[str, Any]]) -> dict[str, Any]:
    before = model(rules)
    return compare(before, apply_plan(before, ops))


def ref(oid: str) -> dict[str, str]:
    return {"id": oid, "type": "Host", "name": oid}


def test_duplicate_object_merge_keeps_every_flow() -> None:
    report = proof(
        BASE,
        [
            {"op": "update_rule", **RULE, "rule": "r3", "set": {"dst_net": [ref("h1")]}},
            {"op": "delete_object", "object": "h1copy", "type": "Host"},
        ],
    )
    # Same addresses through another object: every rule matches exactly what it matched
    # before, so no rule is even touched (a structural proof, no flow needed).
    assert report["ok"] is True
    assert report["policies"] == []
    assert report["flows"] == 0


def test_removing_a_shadowed_rule_keeps_every_flow() -> None:
    rules = [*BASE, rule("r1dup", dst_net=["n1"], dst_port=["https"])]
    report = proof(rules, [{"op": "delete_rule", **RULE, "rule": "r1dup"}])
    assert report["ok"] is True


def test_removing_a_live_rule_shows_exactly_what_changes() -> None:
    report = proof(BASE, [{"op": "delete_rule", **RULE, "rule": "r1"}])
    assert report["ok"] is False
    diffs = report["policies"][0]["differences"]
    assert diffs
    first = diffs[0]
    assert first["flow"]["dst"].startswith("10.1.0.")
    assert first["flow"]["service"] == "TCP/443"
    assert first["before"] == {"verdict": ["ALLOW", None, None], "rule": "R1"}
    assert first["after"] == {"verdict": ["BLOCK", None, None], "rule": "R2"}


def test_a_group_change_reaches_every_rule_using_it() -> None:
    report = proof(
        BASE,
        [
            {
                "op": "update_group",
                "object": "g1",
                "type": "NetworkGroup",
                "members": [ref("n1"), ref("n2")],
            }
        ],
    )
    assert report["ok"] is False
    flows = {(d["flow"]["dst"], d["flow"]["service"]) for d in report["policies"][0]["differences"]}
    assert any(dst.startswith("10.2.0.") and svc == "TCP/443" for dst, svc in flows)
    # 10.2.0.0/24 to 443: default BLOCK before, ALLOW by R1 after.
    first = report["policies"][0]["differences"][0]
    assert first["before"]["verdict"][0] == "DEFAULT:BLOCK"


def test_splitting_a_rule_by_destination_keeps_every_flow() -> None:
    rules = [rule("r6", dst_net=["n1", "n2"], dst_port=["https"]), *BASE]
    report = proof(
        rules,
        [
            {"op": "update_rule", **RULE, "rule": "r6", "set": {"dst_net": [ref("n1")]}},
            {
                "op": "create_rule",
                **RULE,
                "temp": "new:1",
                "copy_from": "r6",
                "insert_after": "r6",
                "name": "R6_SILVER",
                "set": {"dst_net": [ref("n2")]},
            },
        ],
    )
    assert report["ok"] is True, report


def test_merging_adjacent_rules_keeps_every_flow() -> None:
    rules = [
        rule("ra", src_net=["users_a"], dst_net=["n2"], dst_port=["https"]),
        rule("rb", src_net=["users_b"], dst_net=["n2"], dst_port=["https"]),
        *BASE,
    ]
    report = proof(
        rules,
        [
            {
                "op": "update_rule",
                **RULE,
                "rule": "ra",
                "set": {"src_net": [ref("users_a"), ref("users_b")]},
            },
            {"op": "delete_rule", **RULE, "rule": "rb"},
        ],
    )
    assert report["ok"] is True, report


def test_a_wrong_merge_across_a_block_rule_is_caught() -> None:
    # A BLOCK rule between the two: moving rb's sources above it would let them through.
    rules = [
        rule("ra", src_net=["users_a"], dst_net=["n1"], dst_port=["https"]),
        rule("deny_b", "BLOCK", src_net=["users_b"]),
        rule("rb", src_net=["users_b"], dst_net=["n1"], dst_port=["https"]),
    ]
    report = proof(
        rules,
        [
            {
                "op": "update_rule",
                **RULE,
                "rule": "ra",
                "set": {"src_net": [ref("users_a"), ref("users_b")]},
            },
            {"op": "delete_rule", **RULE, "rule": "rb"},
        ],
    )
    assert report["ok"] is False
    diff = report["policies"][0]["differences"][0]
    assert diff["flow"]["src"].startswith("10.51.0.")
    assert (diff["before"]["rule"], diff["after"]["rule"]) == ("DENY_B", "RA")


def test_adding_inspection_is_a_change() -> None:
    report = proof(
        BASE,
        [
            {
                "op": "set_inspection",
                **RULE,
                "rule": "r3",
                "ips": {"id": "ips-1", "name": "Balanced", "type": "IntrusionPolicy"},
            }
        ],
    )
    assert report["ok"] is False
    assert report["policies"][0]["differences"][0]["after"]["verdict"] == ["ALLOW", "ips-1", None]


def test_renames_and_untouched_policies_cost_nothing() -> None:
    report = proof(BASE, [{"op": "rename_object", "object": "h1", "type": "Host", "name": "X"}])
    assert report == {
        "policies": [],
        "flows": 0,
        "differences": 0,
        "exhaustive": True,
        "ok": True,
        "seconds": report["seconds"],
    }
