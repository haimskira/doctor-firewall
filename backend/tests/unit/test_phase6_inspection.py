"""Phase 6 units: intrusion policy strength, IPS exemptions, the set_inspection plan."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.analysis.expand import Leaves
from app.analysis.inspection import (
    CORE_IDENTITY,
    DEMAND_ORDER,
    DOCTRINE,
    NEVER_DECRYPT,
    TLS_APPS,
    TLS_PORTS,
    core_service,
    ips_exemption,
    ips_level,
)
from app.analysis.score import AssetIndex
from app.analysis.space import PortSet
from app.enforce.batching import KIND_ORDER
from app.enforce.plan import PlanBuilder, touched

RULE = {"policy": "p1", "policy_kind": "access", "id": "r1", "name": "APP_TO_GOLD"}


def test_ips_level_by_name_then_base_policy() -> None:
    assert ips_level("Maximum Detection") == 4
    assert ips_level("Security Over Connectivity") == 3
    assert ips_level("Balanced Security and Connectivity") == 2
    assert ips_level("Connectivity Over Security") == 1
    assert ips_level("No Rules Active") == 0
    assert ips_level("IPS-GOLD", "Maximum Detection") == 4
    assert ips_level("IPS-DC", "Balanced") == 2
    assert ips_level("Custom") is None
    assert ips_level(None) is None


def test_doctrine_table() -> None:
    assert DOCTRINE["GOLD"].min_level == 4
    assert DOCTRINE["GOLD"].file_policy
    assert DOCTRINE["SILVER"].file_policy
    assert not DOCTRINE["BRONZE"].file_policy
    assert DOCTRINE["BRONZE"].default_ips == "Balanced Security and Connectivity"


def test_set_inspection_plan() -> None:
    pb = PlanBuilder()
    pb.set_inspection(
        RULE,
        {"action": "TRUST", "ips": None, "file": None},
        ips={"id": "i4", "name": "Maximum Detection"},
        file={"id": "f1", "name": "Block Malware"},
        action="ALLOW",
    )
    plan = pb.build()
    assert plan["executable"] is True
    (op,) = plan["ops"]
    assert op["expect"] == {"name": "APP_TO_GOLD", "action": "TRUST", "ips": None, "file": None}
    assert op["ips"] == {"id": "i4", "name": "Maximum Detection", "type": "IntrusionPolicy"}
    assert op["file"]["type"] == "FilePolicy"
    assert op["action"] == "ALLOW"
    assert touched(plan)["rules"] == {"p1/r1"}

    nothing = PlanBuilder()
    nothing.set_inspection(RULE, {"action": "ALLOW"})
    assert nothing.build()["executable"] is False  # no operation, nothing to run

    prefilter = PlanBuilder()
    prefilter.set_inspection(
        {**RULE, "policy_kind": "prefilter"}, {"action": "FASTPATH"}, ips={"id": "i", "name": "x"}
    )
    assert prefilter.build()["blocked"] == ["unsupported_rule_kind:prefilter"]


def test_inspection_runs_after_tightening() -> None:
    assert KIND_ORDER.index("tighten_ports") < KIND_ORDER.index("add_inspection")
    assert KIND_ORDER.index("add_inspection") < KIND_ORDER.index("remove_dead_rule")


# ---- IPS wherever it can run; fastpath only for heavy / fragile traffic between known systems

ASSETS = AssetIndex(
    [
        ("10.10.0.0/24", "SAN", "SILVER", None),
        ("10.20.0.0/24", "ESX", "GOLD", None),
        ("10.30.0.0/24", "DNS", "CORE", None),
        ("10.99.0.0/16", "USERS", "USERS", "staff"),
    ]
)


def _info(src: list[str] | None, dst: list[str] | None, ports: list[str] | None) -> Any:
    leaves = {}
    if src is not None:
        leaves["src_net"] = Leaves(addresses=set(src))
    if dst is not None:
        leaves["dst_net"] = Leaves(addresses=set(dst))
    if ports is not None:
        leaves["dst_port"] = Leaves(ports=set(ports))
    return SimpleNamespace(unmodelled=False, leaves=leaves)


def _exempt(src: list[str] | None, dst: list[str] | None, ports: list[str] | None) -> list[str]:
    estate: Any = SimpleNamespace(assets=ASSETS)
    return [e.key for e in ips_exemption(estate, _info(src, dst, ports))]


def test_core_is_access_not_inspection_identity_gets_gold_ips() -> None:
    assert DOCTRINE["CORE"].min_level == 2  # DNS / patching: balanced
    assert not DOCTRINE["CORE"].file_policy
    assert CORE_IDENTITY.min_level == 4
    assert not CORE_IDENTITY.file_policy
    assert DEMAND_ORDER.index("SILVER") < DEMAND_ORDER.index("CORE") < DEMAND_ORDER.index("BRONZE")
    dns = ["10.30.0.1"]
    assert core_service(_info(None, dns, ["UDP/53", "TCP/53"])) == "dns_patching"
    assert core_service(_info(None, dns, ["TCP/8530"])) == "dns_patching"
    assert core_service(_info(None, dns, ["TCP/88", "UDP/88"])) == "identity"  # Kerberos
    assert core_service(_info(None, dns, ["UDP/53", "TCP/445"])) == "identity"  # + SMB
    assert core_service(_info(None, dns, ["TCP/9999"])) == "identity"  # unknown: strongest
    assert core_service(_info(None, dns, None)) == "identity"  # any port


def test_ntp_to_core_from_known_sources_is_a_fastpath_candidate() -> None:
    assert _exempt(["10.99.1.0/24"], ["10.30.0.5"], ["UDP/123"]) == ["ntp"]  # users -> CORE
    assert _exempt(["10.20.0.1"], ["10.30.0.5"], ["UDP/123"]) == ["ntp"]
    assert _exempt(["192.0.2.1"], ["10.30.0.5"], ["UDP/123"]) == []  # from outside
    assert _exempt(None, ["10.30.0.5"], ["UDP/123"]) == []  # any source
    assert _exempt(["10.99.1.1"], ["10.20.0.1"], ["UDP/123"]) == []  # NTP to a non-CORE server


def test_storage_and_replication_between_dc_systems_are_fastpath_candidates() -> None:
    assert _exempt(["10.20.0.0/24"], ["10.10.0.5"], ["TCP/3260"]) == ["storage"]
    assert _exempt(["10.20.0.1"], ["10.20.0.2"], ["TCP/8000", "TCP/902"]) == ["replication"]
    assert _exempt(["10.20.0.1"], ["10.10.0.9"], ["TCP/2049", "TCP/8000"]) == [
        "storage",
        "replication",
    ]


def test_anything_outside_the_dc_keeps_the_ips() -> None:
    assert _exempt(["10.99.1.1"], ["10.10.0.5"], ["TCP/3260"]) == []  # users
    assert _exempt(["192.0.2.1"], ["10.10.0.5"], ["TCP/3260"]) == []  # outside / unclassified
    assert _exempt(None, ["10.10.0.5"], ["TCP/3260"]) == []  # any source
    assert _exempt(["10.20.0.1"], ["10.10.0.5"], ["TCP/3260", "TCP/445"]) == []  # SMB too
    assert _exempt(["10.20.0.1"], ["10.10.0.5"], None) == []  # any port
    assert _exempt(["10.20.0.1"], ["10.30.0.1"], ["UDP/53"]) == []  # DNS: CORE gets IPS


def test_routing_bfd_and_management_need_small_explicit_ends() -> None:
    assert _exempt(["192.0.2.1"], ["192.0.2.2"], ["TCP/179"]) == ["routing"]
    assert _exempt(["192.0.2.1"], ["192.0.2.2"], ["OSPF/any"]) == ["routing"]
    assert _exempt(["192.0.2.0/30"], ["192.0.2.4/30"], ["UDP/3784-3785"]) == ["bfd"]
    assert _exempt(["198.51.100.10"], ["10.20.0.0/24"], ["TCP/8305"]) == ["management"]
    assert _exempt(["10.0.0.0/8"], ["192.0.2.2"], ["TCP/179"]) == []  # too broad
    assert _exempt(None, ["192.0.2.2"], ["TCP/179"]) == []  # any


def test_never_decrypt_and_tls_exposure_do_not_overlap() -> None:
    ldaps = PortSet.build(["TCP/636"])
    assert NEVER_DECRYPT.covers(ldaps)
    assert not TLS_PORTS.intersects(ldaps)
    assert "LDAPS" not in TLS_APPS
