"""Dynamic-object candidates: large address lists cross-checked with dynamic objects' content.

Advisory only: every proposal's plan is blocked, so it can never be staged or executed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from app.analysis.dynamic import (
    DYNAMIC_MIN,
    DynamicCatalog,
    DynamicObject,
    recommend_dynamic_objects,
)
from app.analysis.expand import Leaves, literal_leaves
from app.analysis.recommend import Estate, Obj, Ref, RuleInfo
from app.analysis.space import AddressSet
from app.models.inventory import Policy

HOSTS = [f"10.50.{i // 200}.{i % 200 + 1}/32" for i in range(DYNAMIC_MIN + 10)]


class _Estate:
    """What the recommender reads: objects, group leaves, rule samples, cycles."""

    def __init__(self, groups: dict[str, list[str]]) -> None:
        self.objects = {gid: Obj(gid, gid, "network_group", None, False) for gid in groups}
        self.objects["SMALL"] = Obj("SMALL", "SMALL", "network_group", None, False)
        self._groups = {**groups, "SMALL": HOSTS[:5]}
        self.resolver = self

    def leaves(self, oid: str) -> Leaves:
        out = Leaves()
        out.addresses |= set(self._groups.get(oid, []))
        return out

    def leaves_of(self, ref: Ref) -> Leaves:
        if ref.object_id is not None:
            return self.leaves(ref.object_id)
        return literal_leaves(ref.literal or "", ref.literal_kind)

    def cyclic_groups(self) -> frozenset[str]:
        return frozenset()

    def rule_sample(self, rule_ids: Any) -> list[dict[str, Any]]:
        return [{"id": str(i)} for i in rule_ids]


def _catalog(*objects: tuple[str, list[str]], total: int | None = None) -> DynamicCatalog:
    catalog = DynamicCatalog.__new__(DynamicCatalog)
    catalog._single = {}
    catalog.suggested = set()
    catalog.items = [
        DynamicObject(name, name, sorted(addrs), AddressSet.build(addrs), total or len(addrs))
        for name, addrs in objects
    ]
    return catalog


def _rule(rid: int, refs: dict[str, list[Ref]]) -> RuleInfo:
    rule = SimpleNamespace(
        id=rid,
        fmc_id=f"R{rid}",
        rule_index=rid,
        name=f"RULE-{rid}",
        action="ALLOW",
        enabled=True,
        section="mandatory",
        category=None,
        attrs={},
        hit_count=10,
    )
    return RuleInfo(cast(Any, rule), refs, {}, 1, None)


POLICY = cast(Policy, SimpleNamespace(fmc_id="P1", name="ACP", kind="access"))


def _run(groups: dict[str, list[str]], rules: list[RuleInfo], catalog: DynamicCatalog) -> list[Any]:
    return recommend_dynamic_objects(cast(Estate, _Estate(groups)), POLICY, rules, catalog)


def test_a_large_group_matching_a_dynamic_object_is_proposed_as_that_object() -> None:
    rules = [
        _rule(1, {"src_net": [Ref("BIG", "BIG")], "dst_net": [Ref("SMALL", "SMALL")]}),
        _rule(2, {"dst_net": [Ref("BIG", "BIG")]}),
    ]
    (draft,) = _run({"BIG": HOSTS}, rules, _catalog(("DYN_SAME", HOSTS)))
    assert draft.kind == "use_dynamic_object"
    assert draft.plan["executable"] is False
    assert draft.plan["blocked"] == ["dynamic_object_manual"]
    dyn = draft.preview["dynamic"]
    assert dyn["match"] == "identical"
    assert dyn["name"] == "DYN_SAME"
    assert not dyn["create"]
    assert draft.warnings == ["dynamic_runtime_content"]
    first, second = draft.preview["after"]
    assert first["fields"]["src_dyn"] == ["DYN_SAME"]
    assert "src_net" not in first["fields"]
    assert first["fields"]["dst_net"] == ["SMALL"]  # a small group stays
    assert second["fields"]["dst_dyn"] == ["DYN_SAME"]
    assert {t["id"] for t in draft.targets} == {"BIG", "R1", "R2"}


def test_a_close_dynamic_object_shows_what_it_lacks_and_adds() -> None:
    held = [*HOSTS[:-5], "10.99.0.1/32"]  # lacks 5, adds 1: still above 80 %
    (draft,) = _run(
        {"BIG": HOSTS}, [_rule(1, {"src_net": [Ref("BIG", "BIG")]})], _catalog(("DYN_NEAR", held))
    )
    dyn = draft.preview["dynamic"]
    assert dyn["match"] == "close"
    assert dyn["missing_count"] == 5
    assert dyn["extra"] == ["10.99.0.1/32"]
    assert "dynamic_missing_addresses" in draft.warnings
    assert "dynamic_extra_addresses" in draft.warnings


def test_without_a_close_dynamic_object_a_new_one_is_suggested() -> None:
    far = HOSTS[:10]  # far below 80 %
    (draft,) = _run(
        {"BIG": HOSTS}, [_rule(1, {"src_net": [Ref("BIG", "BIG")]})], _catalog(("DYN_FAR", far))
    )
    dyn = draft.preview["dynamic"]
    assert dyn["match"] == "none"
    assert dyn["create"]
    assert dyn["name"] == "DYN-BIG"
    assert dyn["addresses"] == len(HOSTS)
    assert draft.preview["after"][0]["fields"]["src_dyn"] == ["DYN-BIG"]


def test_many_objects_listed_in_a_rule_side_are_a_candidate_too() -> None:
    refs = [Ref(None, h, h, "address") for h in HOSTS]
    (draft,) = _run({}, [_rule(7, {"dst_net": refs})], _catalog())
    dyn = draft.preview["dynamic"]
    assert dyn["source"]["type"] == "rule"
    assert dyn["source"]["side"] == "destination"
    assert dyn["name"] == "DYN-RULE-7-DST"
    assert draft.preview["after"][0]["fields"]["dst_dyn"] == ["DYN-RULE-7-DST"]


def test_small_lists_disabled_and_truncated_cases() -> None:
    assert _run({}, [_rule(1, {"src_net": [Ref("SMALL", "SMALL")]})], _catalog()) == []
    off = _rule(2, {"src_net": [Ref("BIG", "BIG")]})
    off.rule.enabled = False
    assert _run({"BIG": HOSTS}, [off], _catalog()) == []
    # Mappings cut at collection: never called identical, and the comparison says so.
    (draft,) = _run(
        {"BIG": HOSTS},
        [_rule(3, {"src_net": [Ref("BIG", "BIG")]})],
        _catalog(("DYN_CUT", HOSTS), total=5000),
    )
    assert draft.preview["dynamic"]["match"] == "close"
    assert draft.preview["dynamic"]["truncated"]
    assert "dynamic_mappings_truncated" in draft.warnings


def test_fqdn_members_never_make_a_group_identical() -> None:
    class _WithFqdn(_Estate):
        def leaves(self, oid: str) -> Leaves:
            out = super().leaves(oid)
            if oid == "BIG":
                out.address_tokens.add("fqdn:portal.example.com")
            return out

    estate = _WithFqdn({"BIG": HOSTS})
    (draft,) = recommend_dynamic_objects(
        cast(Estate, estate),
        POLICY,
        [_rule(1, {"src_net": [Ref("BIG", "BIG")]})],
        _catalog(("DYN_SAME", HOSTS)),
    )
    assert draft.preview["dynamic"]["match"] == "close"
    assert "dynamic_fqdn_stays" in draft.warnings


def test_two_proposals_never_suggest_the_same_new_name() -> None:
    catalog = _catalog()
    rules = [_rule(1, {"src_net": [Ref("BIG", "BIG")]})]
    first = _run({"BIG": HOSTS}, rules, catalog)[0].preview["dynamic"]["name"]
    second = _run({"BIG": HOSTS}, rules, catalog)[0].preview["dynamic"]["name"]
    assert first == "DYN-BIG"
    assert second == "DYN-BIG-2"
