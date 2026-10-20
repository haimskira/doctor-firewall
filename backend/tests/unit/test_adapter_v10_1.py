"""FMC 10.1 adapter: every mock payload maps; malformed payloads fail loudly."""

from __future__ import annotations

from typing import Any

import pytest
from fmc_mock.seed import generate

from app.collector.service import CollectionError, build_clusters, cluster_policy_links
from app.fmc import normalize
from app.fmc.adapters import UnsupportedFmcVersionError, select_adapter, v10_1
from app.fmc.adapters.v10_1 import AdapterError
from app.fmc.records import ObjectKind, PolicyKind, Ref, RuleField

DATA = generate(clusters=2, rules_per_policy=120, seed=5)


def test_select_adapter() -> None:
    assert select_adapter("10.1.0 (build 117)") is v10_1
    for bad in ("7.4.2", "11.0", "garbage", ""):
        with pytest.raises(UnsupportedFmcVersionError):
            select_adapter(bad)


def test_every_mock_object_maps() -> None:
    for resource, items in DATA.objects.items():
        for item in items:
            rec = v10_1.map_object(resource, item)
            assert rec.fmc_id == item["id"]
            assert rec.kind != ObjectKind.OTHER, item["type"]


def test_object_canonical_values() -> None:
    def obj(resource: str, **fields: Any) -> Any:
        base = {"id": "a1", "name": "x", "type": fields.pop("type")}
        return v10_1.map_object(resource, {**base, **fields})

    assert obj("hosts", type="Host", value="10.0.0.1").value == "10.0.0.1/32"
    assert obj("networks", type="Network", value="10.20.5.7/24").value == "10.20.5.0/24"
    assert obj("ranges", type="Range", value=" 10.0.0.1-10.0.0.9").value == "10.0.0.1-10.0.0.9"
    assert (
        obj("protocolportobjects", type="ProtocolPortObject", protocol="TCP", port="443").value
        == "TCP/443"
    )
    assert obj("protocolportobjects", type="ProtocolPortObject", protocol="UDP").value == "UDP/any"
    assert obj("fqdns", type="FQDN", value="Updates.Example.").value == "updates.example."
    group = obj(
        "networkgroups",
        type="NetworkGroup",
        objects=[{"id": "m1", "name": "h", "type": "Host"}],
        literals=[{"type": "Network", "value": "10.1.0.0/16"}],
    )
    assert group.kind == ObjectKind.NETWORK_GROUP
    assert group.members == (
        Ref(object_id="m1", name="h", fmc_type="Host"),
        Ref(literal="10.1.0.0/16", literal_kind="address"),
    )


@pytest.mark.parametrize(
    ("resource", "item"),
    [
        ("hosts", {"id": "a1", "name": "x", "type": "Host", "value": "999.1.1.1"}),
        ("ranges", {"id": "a1", "name": "x", "type": "Range", "value": "10.0.0.9-10.0.0.1"}),
        ("hosts", {"id": "bad id!", "name": "x", "type": "Host", "value": "10.0.0.1"}),
        ("hosts", {"id": "a1", "name": "x" * 300, "type": "Host", "value": "10.0.0.1"}),
        (
            "protocolportobjects",
            {
                "id": "a1",
                "name": "x",
                "type": "ProtocolPortObject",
                "protocol": "TCP",
                "port": "70000",
            },
        ),
        ("hosts", {"name": "x", "type": "Host", "value": "10.0.0.1"}),
    ],
)
def test_malformed_objects_fail(resource: str, item: dict[str, Any]) -> None:
    with pytest.raises(AdapterError):
        v10_1.map_object(resource, item)


def test_every_mock_rule_maps_in_order() -> None:
    for rules in DATA.rules.values():
        mapped = [v10_1.map_rule(item, i + 1) for i, item in enumerate(rules)]
        assert [r.rule_index for r in mapped] == list(range(1, len(rules) + 1))
        assert {r.section for r in mapped} <= {"Mandatory", "Default"}


def test_rule_fields_and_literals() -> None:
    rule = v10_1.map_rule(
        {
            "id": "r1",
            "name": "R",
            "action": "ALLOW",
            "enabled": False,
            "metadata": {"section": "Mandatory", "category": "DC"},
            "sourceZones": {"objects": [{"id": "z1", "name": "inside", "type": "SecurityZone"}]},
            "sourceNetworks": {"literals": [{"type": "Host", "value": "1.1.1.1"}]},
            "destinationPorts": {
                "literals": [{"type": "PortLiteral", "port": "8080", "protocol": "6"}]
            },
            "applications": {
                "applications": [{"id": "ap1", "name": "HTTP", "type": "Application"}]
            },
            "ipsPolicy": {"id": "i1", "name": "Max", "type": "IntrusionPolicy"},
            "logEnd": True,
        },
        position=42,
    )
    assert rule.rule_index == 42  # no ruleIndex in metadata -> listing position
    assert not rule.enabled
    assert rule.ips_policy == "Max"
    refs = {(f, r.object_id, r.literal) for f, r in rule.refs}
    assert (RuleField.SRC_ZONE, "z1", None) in refs
    assert (RuleField.SRC_NET, None, "1.1.1.1/32") in refs
    assert (RuleField.DST_PORT, None, "TCP/8080") in refs
    assert (RuleField.APP, "ap1", None) in refs


@pytest.mark.parametrize(
    "item",
    [
        {"id": "r1", "name": "R", "action": "PERMIT"},
        {"id": "r1", "name": "R"},
        {
            "id": "r1",
            "name": "R",
            "action": "ALLOW",
            "sourceNetworks": {"literals": [{"type": "Host", "value": "not-an-ip"}]},
        },
        {"id": "r1", "name": "R", "action": "ALLOW", "metadata": {"ruleIndex": 0}},
    ],
)
def test_malformed_rules_fail(item: dict[str, Any]) -> None:
    with pytest.raises(AdapterError):
        v10_1.map_rule(item, 1)


def test_topology_and_network_payloads_map() -> None:
    devices = [v10_1.map_device(d) for d in DATA.devices]
    pairs = [v10_1.map_ha_pair(p) for p in DATA.ha_pairs]
    assignments = [a for a in (v10_1.map_assignment(x) for x in DATA.assignments) if a]
    assert {a.policy_type for a in assignments} == {"AccessPolicy", "FTDNatPolicy"}
    access = [a for a in assignments if a.policy_type == "AccessPolicy"]
    clusters = build_clusters(devices, pairs, access)
    assert len(clusters) == 2
    assert all(c["kind"] == "ha_pair" and len(c["members"]) == 2 for c in clusters)
    assert {c["policy_fmc_id"] for c in clusters} == {p["id"] for p in DATA.policies}
    for policy in DATA.policies:
        assert v10_1.map_policy(policy).default_action == "BLOCK"
        assert [v10_1.map_category(c) for c in DATA.categories[policy["id"]]]
    for items in DATA.hitcounts.values():
        assert all(v10_1.map_hitcount(h).hit_count >= 0 for h in items)
    for device, kinds in DATA.interfaces.items():
        for kind, items in kinds.items():
            mapped = [v10_1.map_interface(kind, i) for i in items]
            assert all(m.ipv4 and "/" in m.ipv4 for m in mapped)
        routes = [v10_1.map_static_route(r) for r in DATA.static_routes[device]]
        assert any(r.gateway and r.gateway.literal for r in routes)
        bgp = v10_1.map_bgp(DATA.bgp_general[device], DATA.bgp[device])
        assert bgp is not None
        assert bgp.neighbors
    assert v10_1.map_bgp([], []) is None


def test_assignment_types_and_standalone_devices() -> None:
    nat = v10_1.map_assignment({"policy": {"id": "n1", "type": "FTDNatPolicy"}, "targets": []})
    assert nat is not None
    assert nat.policy_type == "FTDNatPolicy"
    dev = v10_1.map_device({"id": "d9", "name": "solo", "accessPolicy": {"id": "p9"}})
    clusters = build_clusters([dev], [], [])
    assert clusters[0]["kind"] == "standalone"
    assert clusters[0]["policy_fmc_id"] == "p9"
    pair = v10_1.map_ha_pair(
        {"id": "h1", "name": "x", "primary": {"id": "nope"}, "secondary": {"id": "d9"}}
    )
    with pytest.raises(CollectionError):
        build_clusters([dev], [pair], [])


def test_interface_netmask_forms() -> None:
    assert normalize.interface_cidr("10.1.0.1", "255.255.0.0") == "10.1.0.1/16"
    assert normalize.interface_cidr("10.1.0.1", "24") == "10.1.0.1/24"
    with pytest.raises(AdapterError):
        v10_1.map_interface(
            "physicalinterfaces",
            {
                "id": "i1",
                "name": "e1",
                "ipv4": {"static": {"address": "10.0.0.1", "netmask": "33"}},
            },
        )


# ------------------------------------------------------------------ policy dependencies


def test_every_mock_policy_and_rule_maps() -> None:
    for resource, policies in DATA.policy_lists.items():
        kind = next(k for k, v in v10_1.POLICY_RESOURCES.items() if v == resource)
        for item in policies:
            assert v10_1.map_policy(item, kind).kind == kind
    for (resource, _pid, sub), rules in DATA.policy_rules.items():
        kind = next(k for k, v in v10_1.POLICY_RESOURCES.items() if v == resource)
        rule_type = dict(v10_1.RULE_RESOURCES[kind])[sub]
        mapped = [v10_1.map_any_rule(kind, rule_type, item, i + 1) for i, item in enumerate(rules)]
        assert all(m.rule_index == i + 1 for i, m in enumerate(mapped))


def test_policy_links_are_discovered_from_policy_settings() -> None:
    policy = v10_1.map_policy(
        {
            "id": "acp1",
            "name": "ACP",
            "prefilterPolicySetting": {"id": "pf1", "name": "PF", "type": "PrefilterPolicy"},
            "someNewPolicySetting": {"id": "x1", "name": "X", "type": "Whatever"},
            "notAPolicySetting": "string value is ignored",
            "securityIntelligence": {"id": "si1", "type": "SecurityIntelligencePolicy"},
        },
        PolicyKind.ACCESS,
    )
    assert [(rel, ref.object_id) for rel, ref in policy.links] == [
        ("prefilterPolicySetting", "pf1"),
        ("someNewPolicySetting", "x1"),
    ]
    with pytest.raises(AdapterError):
        v10_1.map_policy({"id": "acp1", "name": "ACP", "prefilterPolicySetting": {"id": "bad id!"}})


def test_prefilter_rule() -> None:
    rule = v10_1.map_prefilter_rule(
        {
            "id": "p1",
            "name": "FP",
            "action": "FASTPATH",
            "ruleType": "PREFILTER",
            "sourceInterfaces": {
                "objects": [{"id": "z1", "name": "outside", "type": "SecurityZone"}]
            },
            "destinationNetworks": {"literals": [{"type": "Network", "value": "10.0.0.0/8"}]},
        },
        3,
    )
    assert (rule.action, rule.rule_type, rule.rule_index) == ("FASTPATH", "PREFILTER", 3)
    assert (RuleField.SRC_ZONE, "z1") in {(f, r.object_id) for f, r in rule.refs}
    with pytest.raises(AdapterError):
        v10_1.map_prefilter_rule({"id": "p1", "action": "ALLOW"}, 1)  # not a prefilter action


def test_generic_rules_validate_action_token() -> None:
    rule = v10_1.map_decryption_rule(
        {
            "id": "d1",
            "action": "DECRYPT_KNOWN_KEY",
            "destinationNetworks": {
                "objects": [{"id": "g1", "name": "GOLD", "type": "NetworkGroup"}]
            },
        },
        1,
    )
    assert rule.name == "rule-1"
    assert (
        v10_1.map_identity_rule({"id": "i1", "name": "x", "action": "NO_AUTH"}, 1).action
        == "NO_AUTH"
    )
    for bad in ("decrypt; drop", "", "lowercase"):
        with pytest.raises(AdapterError):
            v10_1.map_decryption_rule({"id": "d1", "action": bad}, 1)


def test_nat_rules() -> None:
    auto = v10_1.map_nat_rule(
        {
            "id": "a1",
            "natType": "STATIC",
            "originalNetwork": {"id": "h1", "name": "WEB", "type": "Host"},
            "translatedNetwork": {"id": "h2", "name": "WEB_PUB", "type": "Host"},
            "serviceProtocol": "TCP",
            "originalPort": 8443,
            "translatedPort": "443",
        },
        1,
        "AUTO",
    )
    refs = {(f, r.object_id or r.literal) for f, r in auto.refs}
    assert {
        (RuleField.NAT_ORIG_SRC, "h1"),
        (RuleField.NAT_TRANS_SRC, "h2"),
        (RuleField.NAT_ORIG_SPORT, "TCP/8443"),
        (RuleField.NAT_TRANS_SPORT, "TCP/443"),
    } <= refs
    assert (auto.section, auto.rule_type, auto.action, auto.name) == (
        "AUTO",
        "AUTO",
        "STATIC",
        "AUTO NAT 1",
    )
    manual = v10_1.map_nat_rule(
        {
            "id": "m1",
            "natType": "DYNAMIC",
            "section": "AFTER_AUTO",
            "enabled": False,
            "description": "Users PAT",
            "originalSource": {"id": "n1", "name": "U", "type": "Network"},
        },
        2,
        "MANUAL",
    )
    assert (manual.section, manual.enabled, manual.name) == ("AFTER_AUTO", False, "Users PAT")
    for bad in (
        {"id": "m1", "natType": "NOPE"},
        {"id": "m1", "natType": "STATIC", "section": "MIDDLE"},
    ):
        with pytest.raises(AdapterError):
            v10_1.map_nat_rule(bad, 1, "MANUAL")
    with pytest.raises(AdapterError):
        v10_1.map_nat_rule(
            {"id": "a1", "natType": "STATIC", "originalPort": 99999, "serviceProtocol": "TCP"},
            1,
            "AUTO",
        )
    with pytest.raises(AdapterError):
        v10_1.map_any_rule(PolicyKind.INTRUSION, None, {}, 1)


def test_cluster_policy_links() -> None:
    devices = [v10_1.map_device(d) for d in DATA.devices]
    pairs = [v10_1.map_ha_pair(p) for p in DATA.ha_pairs]
    assignments = [a for a in (v10_1.map_assignment(x) for x in DATA.assignments) if a]
    clusters = build_clusters(
        devices, pairs, [a for a in assignments if a.policy_type == "AccessPolicy"]
    )
    access = [v10_1.map_policy(p) for p in DATA.policies]
    rows = cluster_policy_links(clusters, assignments, access)
    by_cluster: dict[str, set[str]] = {}
    for row in rows:
        by_cluster.setdefault(row["cluster_fmc_id"], set()).add(row["via"])
    assert all(vias == {"assignment", "prefilterPolicySetting"} for vias in by_cluster.values())
    assert len(rows) == 3 * len(clusters)  # access + NAT (assigned) + prefilter (linked)
