"""Asset discovery: segments, populations, domains and systems from cross-checked evidence."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.analysis.discovery import Facts, Unit, discover, tokens
from app.api.discovery import Role
from app.models.assets import SEGMENT_ROLES


def _facts(
    units: list[Unit],
    *,
    groups: dict[str, tuple[str, set[str]]] | None = None,
    dynamics: dict[str, tuple[str, set[str]]] | None = None,
    interfaces: list[dict[str, Any]] | None = None,
    routes: list[dict[str, Any]] | None = None,
    realms: Counter[str] | None = None,
    live: set[str] | None = None,
) -> Facts:
    groups = groups or {}
    dynamics = dynamics or {}
    by_net = {u.network: u for u in units}
    for gid, (_name, members) in groups.items():
        for n in members:
            by_net.setdefault(n, Unit(n)).groups.add(gid)
    for did, (_name, members) in dynamics.items():
        for n in members:
            by_net.setdefault(n, Unit(n)).dynamics.add(did)
    return Facts(
        by_net,
        groups,
        dynamics,
        interfaces or [],
        routes or [],
        realms or Counter(),
        [],
        live if live is not None else set(groups),
    )


def _unit(network: str, *names: str, **behaviour: Any) -> Unit:
    u = Unit(network, names=set(names))
    for key, value in behaviour.items():
        setattr(u, key, value)
    return u


def _iface(ifname: str, network: str, zone: str = "", address: str = "") -> dict[str, Any]:
    return {
        "cluster": "FTD-1",
        "interface": "Gi0/1",
        "ifname": ifname,
        "zone": zone,
        "network": network,
        "address": address or network.split("/")[0],
    }


def test_roles_match_the_model() -> None:
    assert set(Role.__args__) == set(SEGMENT_ROLES)  # type: ignore[attr-defined]


def test_tokens_split_case_digits_and_punctuation() -> None:
    assert tokens("VC-SDA-Users_AH01") == ["vc", "sda", "users", "ah", "01"]
    assert tokens("coreSwitch2") == ["core", "switch", "2"]


def test_interfaces_are_gateway_segments_and_the_default_route_faces_outside() -> None:
    facts = _facts(
        [],
        interfaces=[
            _iface("inet", "100.64.0.0/24", zone="Z_EDGE"),
            _iface("srv-farm", "10.20.0.0/24", zone="Z_A"),
        ],
        routes=[{"cluster": "FTD-1", "ifname": "inet", "network": "0.0.0.0/0", "gateway": "x"}],
    )
    segs = {s.network: s for s in discover(facts).segments}
    assert segs["100.64.0.0/24"].role == "outside"  # by the default route, not by its name
    assert segs["100.64.0.0/24"].gateway is True
    assert segs["10.20.0.0/24"].role == "dc_servers"
    assert segs["10.20.0.0/24"].in_dc is True


def test_users_are_sda_with_sgt_evidence_and_legacy_without() -> None:
    facts = _facts(
        [
            _unit("10.1.0.0/24", "NET_USERS_FLOOR1", sgt_hits=4),
            _unit("10.2.0.0/24", "NET_USERS_FLOOR2"),
            _unit("10.3.0.0/24", "Legacy-Users-B"),
            _unit("10.4.0.0/24", "VoIP-Phones-SDA"),
        ]
    )
    segs = {s.network: s for s in discover(facts).segments}
    assert segs["10.1.0.0/24"].role == "sda_users"
    assert any(e["source"] == "identity" for e in segs["10.1.0.0/24"].evidence)
    assert segs["10.2.0.0/24"].role == "legacy_users"
    assert segs["10.3.0.0/24"].role == "legacy_users"
    assert segs["10.4.0.0/24"].role == "vc_sda"


def test_a_dynamic_object_is_recognised_by_what_it_holds() -> None:
    """No vocabulary in its name: three of its five addresses are switches by name, so the
    dynamic object tracks network devices and lends that role to the other two."""
    switches = [_unit(f"10.9.0.{i}/32", f"core-switch-{i}") for i in range(1, 4)]
    unknown = [_unit("10.9.0.20/32"), _unit("10.9.0.21/32")]
    facts = _facts(
        [*switches, *unknown],
        dynamics={"d1": ("DYN_FABRIC_INVENTORY", {u.network for u in switches + unknown})},
    )
    result = discover(facts)
    assert result.unit_roles["10.9.0.20/32"] == "network_devices"
    devices = next(s for s in result.systems if s.name.startswith("Network devices"))
    assert {c[0] for c in devices.components} >= {"10.9.0.20/32", "10.9.0.21/32"}
    assert devices.tier == "CORE"


def test_domains_are_learnt_from_names_recurring_across_populations() -> None:
    facts = _facts(
        [
            _unit("10.10.0.0/24", "AH-SDA-USERS", sgt_hits=1),
            _unit("10.11.0.0/24", "AH-Legacy-Users"),
            _unit("10.12.0.0/24", "OA-SDA-USERS", sgt_hits=1),
            _unit("10.13.0.0/24", "OA-LEGACY-USERS"),
            _unit("10.14.0.0/24", "LOTR-VC-LEGACY-USERS"),
            _unit("10.15.0.0/24", "LOTR-SDA-USERS", sgt_hits=1),
            _unit("10.16.0.0/24", "FLOOR3-USERS"),  # one population only: not a domain
        ]
    )
    result = discover(facts)
    assert {"ah", "oa", "lotr"} <= set(result.domains)
    assert "floor3" not in result.domains
    segs = {s.network: s for s in result.segments}
    assert segs["10.10.0.0/24"].domain == "AH"
    assert segs["10.14.0.0/24"].role == "vc_legacy"
    assert segs["10.14.0.0/24"].domain == "LOTR"
    populations = {s.name for s in result.systems if s.kind == "user_segment"}
    assert {"SDA-USERS AH", "LEGACY-USERS OA", "VC-LEGACY LOTR"} <= populations


def test_realm_prefixes_of_user_conditions_are_domains() -> None:
    facts = _facts([_unit("10.20.0.0/24", "CORP-USERS")], realms=Counter({"corp": 3}))
    result = discover(facts)
    assert "corp" in result.domains
    assert result.domains["corp"][0]["source"] == "identity"


def test_servers_group_into_systems_by_used_group_then_by_name() -> None:
    servers = {
        "10.30.0.10/32": "H_PAY-DB_01",
        "10.30.0.11/32": "H_PAY-APP_02",
        "10.30.0.20/32": "srv-crm-web1",
        "10.30.0.21/32": "srv-crm-web2",
        "10.30.0.30/32": "H_LONELY_01",
    }
    units = [_unit(n, name, as_dst=3, dst_ports=Counter({1433: 2})) for n, name in servers.items()]
    facts = _facts(
        units,
        groups={
            "g-pay": ("GRP_SYS_PAYMENTS", {"10.30.0.10/32", "10.30.0.11/32"}),
            "g-unused": ("GRP_OLD_COPY", {"10.30.0.20/32", "10.30.0.21/32"}),
        },
        interfaces=[_iface("gold", "10.30.0.0/24", zone="Z_GOLD")],
        live={"g-pay"},  # the unused group never defines a system
    )
    systems = {s.name: s for s in discover(facts).systems}
    assert set(systems["PAYMENTS"].components) == {
        ("10.30.0.10/32", "H_PAY-DB_01", "DB"),
        ("10.30.0.11/32", "H_PAY-APP_02", "App"),
    }
    assert systems["PAYMENTS"].tier == "GOLD"  # behind a GOLD zone
    assert {c[0] for c in systems["CRM"].components} == {"10.30.0.20/32", "10.30.0.21/32"}
    assert systems["H_LONELY_01"].kind == "server"


def test_a_name_family_too_big_for_one_system_is_split() -> None:
    units = [
        _unit(
            f"10.40.{i // 200}.{i % 200 + 1}/32",
            f"H_DMZ_{'WEB' if i % 2 else 'APP'}_{i}",
            as_dst=1,
            dst_ports=Counter({443: 1}),
        )
        for i in range(140)
    ]
    facts = _facts(units, interfaces=[_iface("dmz", "10.40.0.0/16", zone="Z_DMZ")])
    names = {s.name for s in discover(facts).systems if s.kind == "system"}
    assert {"DMZ-WEB", "DMZ-APP"} <= names


def test_nothing_without_enough_evidence() -> None:
    facts = _facts([_unit("10.50.0.0/24", "NET_BLUE_42")])
    result = discover(facts)
    assert "10.50.0.0/24" not in result.unit_roles
    assert result.systems == []
