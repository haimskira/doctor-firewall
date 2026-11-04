"""Review fixes: unmodelled rule conditions, value merges, group cycles, verdicts, protocols."""

from __future__ import annotations

import ipaddress
import random
from typing import Any, cast

import pytest

from app.analysis import inspection
from app.analysis.basic import VALUE_KINDS
from app.analysis.compact import _member
from app.analysis.expand import Leaves, Resolver, RuleSpace, ace_estimate, build_space
from app.analysis.policy_scope import _explicit
from app.analysis.recommend import (
    VALUE_MERGE_KINDS,
    Estate,
    Obj,
    Ref,
    RuleInfo,
    _merge_key,
    recommend_merge_rules,
)
from app.analysis.redundancy import redundant
from app.analysis.score import AssetIndex
from app.analysis.shadow import analyse_order, analyse_order_naive, verdict
from app.analysis.space import AddressSet
from app.collector.store import _signature
from app.enforce.proof import Model, PolicyModel, RuleModel, compare, condition_refs
from app.fmc import normalize
from app.fmc.adapters import v10_1
from app.fmc.records import ObjectKind, RuleField
from app.models.inventory import Policy, Rule

URL_CATEGORY = {
    "type": "UrlCategoryAndReputation",
    "category": {"id": "c1", "name": "Gambling", "type": "URLCategory"},
    "reputation": "UNTRUSTED",
}


def _access_rule(**fields: Any) -> dict[str, Any]:
    return {"id": "r1", "name": "R", "action": "BLOCK", **fields}


# ------------------------------------------------------------------ adapter: conditions


def test_url_categories_time_ranges_vlans_and_filters_are_recorded() -> None:
    rule = v10_1.map_rule(
        _access_rule(
            urls={"urlCategoriesWithReputation": [URL_CATEGORY]},
            timeRangeObjects=[{"id": "t1", "name": "WORK", "type": "TimeRange"}],
            vlanTags={
                "objects": [{"id": "v1", "name": "V", "type": "VlanTag"}],
                "literals": [{"type": "VlanTagLiteral", "startTag": 10, "endTag": 20}],
            },
            applications={"inlineApplicationFilters": [{"risks": [{"id": "VERY_HIGH"}]}]},
        ),
        1,
    )
    assert rule.attrs["unmodelled"] == [
        "inline_application_filters",
        "time_range",
        "url_categories",
        "vlan_literals",
    ]
    conditions = rule.attrs["conditions"]
    assert set(conditions) == {"app", "time", "url", "vlan"}
    assert conditions["vlan"] == ["vlan:10-20"]
    assert conditions["time"] == ["time:t1"]
    # The VLAN object is still a reference; the literal is not lost.
    assert (RuleField.VLAN, "v1") in {(f, r.object_id) for f, r in rule.refs}


def test_plain_rule_has_no_unmodelled_conditions() -> None:
    rule = v10_1.map_rule(_access_rule(urls={"urlCategoriesWithReputation": []}), 1)
    assert "unmodelled" not in rule.attrs
    assert "conditions" not in rule.attrs


def test_tunnel_prefilter_rule_is_unmodelled_and_bidirectional_widens() -> None:
    rule = v10_1.map_prefilter_rule(
        {
            "id": "p1",
            "name": "T",
            "action": "FASTPATH",
            "ruleType": "TUNNEL",
            "encapsulationPorts": ["GRE"],
            "bidirectional": True,
        },
        1,
    )
    assert rule.attrs["unmodelled"] == ["bidirectional", "tunnel"]
    assert list(rule.attrs["conditions"]) == ["tunnel"]


def test_decryption_tls_conditions_are_unmodelled() -> None:
    rule = v10_1.map_decryption_rule(
        {
            "id": "d1",
            "name": "D",
            "action": "DO_NOT_DECRYPT",
            "cipherSuites": [{"id": "cs1", "name": "TLS_RSA_WITH_RC4_128_SHA"}],
        },
        1,
    )
    assert rule.attrs["unmodelled"] == ["tls_conditions"]
    assert list(rule.attrs["conditions"]) == ["other"]


# ------------------------------------------------------------------ space and shadowing


def _rs(
    index: int, action: str, attrs: dict[str, Any] | None = None, **fields: Leaves
) -> RuleSpace:
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
        space=build_space(fields, attrs),
        ace_count=ace_estimate(fields),
        leaf_counts={},
    )


def _attrs(item: dict[str, Any]) -> dict[str, Any]:
    return dict(v10_1.map_rule(item, 1).attrs)


CATEGORY_ATTRS = _attrs(_access_rule(urls={"urlCategoriesWithReputation": [URL_CATEGORY]}))


def test_rule_with_url_category_never_shadows_a_later_rule() -> None:
    web = Leaves(addresses={"10.1.0.0/16"})
    rules = [
        _rs(1, "BLOCK", CATEGORY_ATTRS),  # blocks gambling sites only, not everything
        _rs(2, "ALLOW", dst_net=web),
    ]
    for analyse in (analyse_order, analyse_order_naive):
        shadows, _ = analyse(rules)
        assert shadows == []


def test_rule_with_url_category_is_shadowed_by_a_fully_modelled_rule() -> None:
    rules = [_rs(1, "BLOCK"), _rs(2, "ALLOW", CATEGORY_ATTRS)]
    shadows, _ = analyse_order(rules)
    assert [(s.rule.fmc_id, s.by.fmc_id) for s in shadows] == [("r2", "r1")]


def test_category_joins_the_url_field_instead_of_narrowing_it_away() -> None:
    # The rule matches URL object u1 OR the category: a rule matching only u1 does not cover it.
    attrs = CATEGORY_ATTRS
    earlier = _rs(1, "BLOCK", url=Leaves(tokens={"u1"}))
    later = _rs(2, "ALLOW", attrs, url=Leaves(tokens={"u1"}))
    assert not earlier.space.covers(later.space)


def test_bidirectional_rule_is_never_covered() -> None:
    attrs = {"unmodelled": ["bidirectional"], "conditions": {}}
    assert not build_space({}).covers(build_space({}, attrs))


def test_identical_rules_with_unmodelled_conditions_differ() -> None:
    a = v10_1.map_rule({**_access_rule(urls={"urlCategoriesWithReputation": [URL_CATEGORY]})}, 1)
    b = v10_1.map_rule(
        {**_access_rule(urls={"urlCategoriesWithReputation": [URL_CATEGORY]}), "id": "r2"}, 2
    )
    assert _signature(a) != _signature(b)
    plain_a = v10_1.map_rule(_access_rule(), 1)
    plain_b = v10_1.map_rule({**_access_rule(), "id": "r2"}, 2)
    assert _signature(plain_a) == _signature(plain_b)


def test_proof_sees_a_removed_rule_behind_a_url_category_rule() -> None:
    def rule(key: str, action: str, attrs: dict[str, Any] | None = None) -> RuleModel:
        refs: dict[str, list[tuple[str | None, str | None, str | None]]] = {
            "dst_net": [("web", None, None)]
        }
        for fld, members in condition_refs(attrs).items():
            refs.setdefault(fld, []).extend(members)
        return RuleModel(key, key.upper(), True, action, None, None, refs)

    def model(rules: list[RuleModel]) -> Model:
        return Model(
            {"web": ("network", "10.1.0.0/16")},
            {},
            {"p1": PolicyModel("p1", "ACP", "access", "BLOCK", rules)},
        )

    before = model([rule("block", "BLOCK", CATEGORY_ATTRS), rule("allow", "ALLOW")])
    after = model([rule("block", "BLOCK", CATEGORY_ATTRS)])
    assert compare(before, after)["differences"] > 0


# ------------------------------------------------------------------ verdicts


def test_fastpath_and_analyze_are_different_verdicts() -> None:
    assert verdict("FASTPATH") != verdict("ANALYZE")
    assert verdict("FASTPATH") != verdict("ALLOW")
    assert verdict("ALLOW") == verdict("TRUST") == "permit"
    assert verdict("BLOCK_RESET") == "deny"
    rules = [_rs(1, "FASTPATH"), _rs(2, "ANALYZE")]
    shadows, _ = analyse_order(rules)
    assert [s.conflict for s in shadows] == [True]


# ------------------------------------------------------------------ rule merges


def _info(fmc_id: str, attrs: dict[str, Any] | None = None, **columns: Any) -> RuleInfo:
    rule = Rule(
        id=int(fmc_id[1:]),
        fmc_id=fmc_id,
        policy_fmc_id="p",
        rule_index=int(fmc_id[1:]),
        section="Default",
        category="",
        name=fmc_id,
        enabled=True,
        action="ALLOW",
        ips_policy_id=None,
        file_policy_id=None,
        variable_set=columns.get("variable_set"),
        log_begin=False,
        log_end=False,
        send_events=columns.get("send_events", False),
        rule_type=columns.get("rule_type"),
        attrs=attrs or {},
    )
    refs = {
        "src_net": [Ref(f"s{fmc_id}", f"S{fmc_id}")],
        "dst_net": [Ref("d", "D")],
    }
    return RuleInfo(rule, refs, {}, 1, None)


@pytest.mark.parametrize(
    "columns",
    [{"variable_set": "Other"}, {"send_events": True}, {"rule_type": "TUNNEL"}],
)
def test_merge_key_sees_settings_that_change_behaviour(columns: dict[str, Any]) -> None:
    assert _merge_key(_info("r1")) != _merge_key(_info("r2", **columns))


def test_rules_with_unmodelled_conditions_are_never_merged() -> None:
    other = _attrs(
        _access_rule(
            urls={
                "urlCategoriesWithReputation": [
                    {**URL_CATEGORY, "category": {"id": "c2", "name": "News"}}
                ]
            }
        )
    )
    rules = [_info("r1", CATEGORY_ATTRS), _info("r2", other)]
    assert _merge_key(rules[0]) != _merge_key(rules[1])
    policy = Policy(fmc_id="p", name="ACP", kind="access")
    assert recommend_merge_rules(cast(Estate, object()), policy, rules) == []
    same = [_info("r1", CATEGORY_ATTRS), _info("r2", CATEGORY_ATTRS)]
    assert recommend_merge_rules(cast(Estate, object()), policy, same) == []


# ------------------------------------------------------------------ object merges


def test_only_real_values_merge() -> None:
    assert {k.value for k in VALUE_KINDS} == VALUE_MERGE_KINDS
    for kind in (ObjectKind.DYNAMIC, ObjectKind.FQDN, ObjectKind.SGT, ObjectKind.OTHER):
        assert kind.value not in VALUE_MERGE_KINDS
    for kind in (ObjectKind.HOST, ObjectKind.NETWORK, ObjectKind.RANGE, ObjectKind.PORT):
        assert kind.value in VALUE_MERGE_KINDS


class _Objects:
    def __init__(self, objects: dict[str, Obj], members: dict[str, list[Ref]]) -> None:
        self.objects = objects
        self.members = members
        self._cyclic: frozenset[str] | None = None
        self.resolver = Resolver(
            {o.fmc_id: (o.kind, o.value) for o in objects.values()},
            {g: [(m.object_id, None, None) for m in refs] for g, refs in members.items()},
            frozenset(o.fmc_id for o in objects.values() if o.overridable),
        )

    def cyclic_groups(self) -> frozenset[str]:
        return Estate.cyclic_groups(cast(Estate, self))


def test_overridable_member_is_never_compacted_and_resolves_opaque() -> None:
    estate = _Objects(
        {"h": Obj("h", "h", "host", "10.0.0.5/32", False, overridable=True)},
        {},
    )
    member = _member(cast(Estate, estate), Ref("h", "h"))
    assert not member.candidate
    assert member.intervals == []
    leaves = estate.resolver.leaves("h")
    assert leaves.addresses == set()
    assert leaves.address_tokens == {"device:h"}


# ------------------------------------------------------------------ redundancy and cycles


def _group(gid: str, overridable: bool = False) -> Obj:
    return Obj(gid, gid, "network_group", None, False, overridable=overridable)


def test_cycle_never_empties_a_rule_field() -> None:
    estate = _Objects(
        {"A": _group("A"), "B": _group("B"), "h": Obj("h", "h", "host", "10.0.0.1/32", False)},
        {"A": [Ref("B", "B"), Ref("h", "h")], "B": [Ref("A", "A")]},
    )
    refs = [Ref("A", "A"), Ref("B", "B")]
    keep, gone = redundant(cast(Estate, estate), {}, refs)
    assert keep == refs
    assert gone == []


def test_removed_container_does_not_justify_a_removal() -> None:
    estate = _Objects(
        {
            "outer": _group("outer"),
            "inner": _group("inner"),
            "h": Obj("h", "h", "host", "10.0.0.1/32", False),
        },
        {"outer": [Ref("inner", "inner")], "inner": [Ref("h", "h")]},
    )
    refs = [Ref("h", "h"), Ref("inner", "inner"), Ref("outer", "outer")]
    keep, gone = redundant(cast(Estate, estate), {}, refs)
    assert keep == [Ref("outer", "outer")]
    assert {g.object_id for _r, g, _c in gone} == {"outer"}


def test_overridable_group_never_stands_for_its_members() -> None:
    estate = _Objects(
        {"G": _group("G", overridable=True), "h": Obj("h", "h", "host", "10.0.0.1/32", False)},
        {"G": [Ref("h", "h")]},
    )
    refs = [Ref("G", "G"), Ref("h", "h")]
    assert redundant(cast(Estate, estate), {}, refs) == (refs, [])


# ------------------------------------------------------------------ SSL exposure per policy


def test_inbound_decryption_is_checked_against_the_linked_policy_only() -> None:
    advisor = inspection.SslAdvisor.__new__(inspection.SslAdvisor)
    gold_a = inspection._Node("GOLD", "SYS-A", AddressSet.build(["10.1.0.0/24"]))
    gold_b = inspection._Node("GOLD", "SYS-B", AddressSet.build(["10.2.0.0/24"]))
    advisor.exposed = {"acpA": {("GOLD", "SYS-A"): gold_a}, "acpB": {("GOLD", "SYS-B"): gold_b}}
    advisor.access_policies = {
        "acpA": Policy(fmc_id="acpA", name="A", kind="access", links=[{"id": "dA"}]),
        "acpB": Policy(fmc_id="acpB", name="B", kind="access", links=[{"id": "dB"}]),
    }
    advisor.decryption = [
        (Policy(fmc_id="dA", name="DEC-A", kind="decryption"), []),
        (Policy(fmc_id="dB", name="DEC-B", kind="decryption"), []),
    ]
    targets = {
        (p.fmc_id if p else None): sorted(n.system for n in nodes)
        for p, _rules, nodes in advisor._targets()
    }
    assert targets == {"dA": ["SYS-A"], "dB": ["SYS-B"]}


def test_explicit_policies_override_the_document_scan() -> None:
    assert _explicit({"policies": ["b", "a"]}) == ["a", "b"]
    assert _explicit({"policies": []}) == []
    assert _explicit({"literal": {}}) is None


# ------------------------------------------------------------------ collector values


@pytest.mark.parametrize("name", ["IGMP", "pim", "OSPFIGP", "EIGRP", "IPIP", "112"])
def test_other_ip_protocols_are_accepted(name: str) -> None:
    assert normalize.port_spec(name, None) == f"{name.upper()}/any"


def test_unknown_protocol_words_still_fail() -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        normalize.protocol("BOGUS")


def _icmp(**fields: Any) -> str | None:
    item = {"id": "i1", "name": "x", "type": "ICMPV4Object", **fields}
    return v10_1.map_object("icmpv4objects", item).value


def test_icmp_type_zero_is_echo_reply_not_any() -> None:
    assert _icmp(icmpType=0) == "ICMP/0"
    assert _icmp(icmpType="0", code=0) == "ICMP/0/0"
    assert _icmp(icmpType="Any") == "ICMP/any"
    assert _icmp() == "ICMP/any"


def test_icmp_literal_keeps_its_code() -> None:
    rule = v10_1.map_rule(
        _access_rule(
            destinationPorts={
                "literals": [
                    {"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": 3, "code": 4}
                ]
            }
        ),
        1,
    )
    assert {r.literal for _f, r in rule.refs} == {"ICMP/3/4"}


# ------------------------------------------------------------------ asset index


def _unclassified_reference(index: AssetIndex, addresses: AddressSet) -> bool:
    for version, intervals in ((4, addresses.v4), (6, addresses.v6)):
        blocks = sorted((e.lo, e.hi) for e in index.entries if e.version == version)
        for lo, hi in intervals:
            cursor = lo
            for b_lo, b_hi in blocks:
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


def test_unclassified_matches_the_reference_scan() -> None:
    rng = random.Random(7)  # noqa: S311 - reproducible test data, not security
    nets = [
        f"10.{rng.randrange(4)}.{rng.randrange(8)}.0/{rng.choice([22, 24, 26])}" for _ in range(30)
    ]
    index = AssetIndex([(n, f"S{i}", "GOLD", None) for i, n in enumerate(nets)])
    for _ in range(300):
        base = int(ipaddress.IPv4Address("10.0.0.0")) + rng.randrange(4 * 65536)
        size = rng.choice([1, 16, 256, 1024])
        first, last = ipaddress.IPv4Address(base), ipaddress.IPv4Address(base + size - 1)
        addresses = AddressSet.build([f"{first}-{last}"])
        assert index.unclassified(addresses) == _unclassified_reference(index, addresses)
