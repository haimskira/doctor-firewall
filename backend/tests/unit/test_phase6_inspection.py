"""Phase 6 units: IPS exemptions, the set_inspection plans (IPS / file), Decrypt-Resign."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.analysis.expand import Leaves
from app.analysis.inspection import (
    DEMAND_ORDER,
    DOCTRINE,
    HTTPS_APPS,
    HTTPS_PORT,
    NEVER_DECRYPT,
    SslAdvisor,
    ips_exemption,
    ips_level,
)
from app.analysis.score import AssetIndex
from app.analysis.space import PortSet
from app.enforce.batching import KIND_ORDER, Item, conflicts, separate
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
    # One intrusion policy for the organisation: the tier only decides the file policy and urgency.
    assert DOCTRINE["GOLD"].file_policy
    assert DOCTRINE["SILVER"].file_policy
    assert not DOCTRINE["CORE"].file_policy
    assert not DOCTRINE["BRONZE"].file_policy
    assert DOCTRINE["GOLD"].priority > DOCTRINE["SILVER"].priority > DOCTRINE["BRONZE"].priority
    assert DEMAND_ORDER.index("SILVER") < DEMAND_ORDER.index("CORE") < DEMAND_ORDER.index("BRONZE")


def test_set_inspection_plan() -> None:
    pb = PlanBuilder()
    pb.set_inspection(
        RULE,
        {"action": "TRUST", "ips": None, "file": None},
        ips={"id": "i4", "name": "Maximum Detection"},
        action="ALLOW",
    )
    plan = pb.build()
    assert plan["executable"] is True
    (op,) = plan["ops"]
    # An intrusion-policy op expects the action and the intrusion policy, not the file policy.
    assert op["expect"] == {"name": "APP_TO_GOLD", "action": "TRUST", "ips": None}
    assert op["ips"] == {"id": "i4", "name": "Maximum Detection", "type": "IntrusionPolicy"}
    assert "file" not in op
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


def test_file_policy_plan_expects_only_the_file_policy() -> None:
    pb = PlanBuilder()
    pb.set_inspection(
        RULE,
        {"action": "ALLOW", "ips": "i4", "file": None},
        file={"id": "f1", "name": "Block Malware"},
    )
    (op,) = pb.build()["ops"]
    assert op["expect"] == {"name": "APP_TO_GOLD", "file": None}
    assert op["file"] == {"id": "f1", "name": "Block Malware", "type": "FilePolicy"}
    assert "ips" not in op
    assert "action" not in op


def _item(key: str, kind: str, *ops: dict[str, Any]) -> Item:
    plan = {"version": 1, "ops": list(ops), "executable": True, "blocked": []}
    return Item(key, kind, key, plan, frozenset({"c"}))


def _ips_plan() -> dict[str, Any]:
    pb = PlanBuilder()
    pb.set_inspection(
        RULE, {"action": "ALLOW", "ips": None, "file": None}, ips={"id": "i", "name": "n"}
    )
    op: dict[str, Any] = pb.build()["ops"][0]
    return op


def _file_plan() -> dict[str, Any]:
    pb = PlanBuilder()
    pb.set_inspection(
        RULE, {"action": "ALLOW", "ips": None, "file": None}, file={"id": "f", "name": "n"}
    )
    op: dict[str, Any] = pb.build()["ops"][0]
    return op


def test_ips_and_file_on_one_rule_stage_together_but_nothing_else_does() -> None:
    ips = _item("ips", "add_inspection", _ips_plan())
    file = _item("file", "add_file_policy", _file_plan())
    assert conflicts([ips, file]) == []
    taken, held = separate([ips, file])
    assert [i.key for i in taken] == ["ips", "file"]
    assert held == []

    # Two intrusion-policy ops on the same rule still clash (second one is held).
    other_ips = _item("ips2", "add_inspection", _ips_plan())
    assert [c.reason for c in conflicts([ips, other_ips])] == ["same_rule"]
    assert [
        c.second for c in conflicts([file, _item("file2", "add_file_policy", _file_plan())])
    ] == ["file2"]
    # A rule edit (any other operation) on the rule clashes with both.
    edit = {"op": "update_rule", "policy": "p1", "rule": "r1", "set": {}}
    rule_edit = _item("edit", "tighten_ports", edit)
    assert [c.reason for c in conflicts([rule_edit, ips])] == ["same_rule"]
    assert [c.reason for c in conflicts([file, rule_edit])] == ["same_rule"]
    # An old plan that wrote both policies in one op clashes with each of the two.
    both = _item("both", "add_inspection", {**_ips_plan(), "file": _file_plan()["file"]})
    assert [c.reason for c in conflicts([both, file])] == ["same_rule"]


def test_inspection_runs_after_tightening() -> None:
    assert KIND_ORDER.index("tighten_ports") < KIND_ORDER.index("add_inspection")
    assert KIND_ORDER.index("add_inspection") < KIND_ORDER.index("add_file_policy")
    assert KIND_ORDER.index("add_file_policy") < KIND_ORDER.index("remove_dead_rule")


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


def test_never_decrypt_and_https_do_not_overlap() -> None:
    ldaps = PortSet.build(["TCP/636"])
    assert NEVER_DECRYPT.covers(ldaps)
    assert not HTTPS_PORT.intersects(ldaps)
    assert "LDAPS" not in HTTPS_APPS
    assert "IMAPS" not in HTTPS_APPS  # only HTTPS is decrypted


# ---- Decrypt-Resign: HTTPS only, GOLD / SILVER only

SSL_ASSETS = [
    SimpleNamespace(network="10.20.0.0/24", system="SQL-FIN", tier="GOLD"),
    SimpleNamespace(network="10.30.0.0/24", system="PORTAL", tier="SILVER"),
    SimpleNamespace(network="10.40.0.0/24", system="DNS", tier="CORE"),
]
ACP: Any = SimpleNamespace(fmc_id="acp", name="ACP", kind="access", links=[{"id": "ssl"}])
SSL: Any = SimpleNamespace(fmc_id="ssl", name="SSL", kind="decryption", links=[])


def _access(dst: str, ports: list[str], tiers: tuple[str, ...], apps: tuple[str, ...] = ()) -> Any:
    rule = SimpleNamespace(enabled=True, rule_index=1, name="WEB", fmc_id="r1", action="ALLOW")
    refs = {"app": [SimpleNamespace(label=a) for a in apps]}
    return SimpleNamespace(
        rule=rule,
        permit=True,
        unmodelled=False,
        refs=refs,
        score=SimpleNamespace(shadowed_by=None, dst_tiers=tiers),
        leaves={"dst_net": Leaves(addresses={dst}), "dst_port": Leaves(ports=set(ports))},
    )


def _decrypt(action: str, dst: list[str], ports: list[str] | None) -> Any:
    rule = SimpleNamespace(enabled=True, rule_index=1, name=action, fmc_id=action, action=action)
    leaves = {"dst_net": Leaves(addresses=set(dst))}
    if ports is not None:
        leaves["dst_port"] = Leaves(ports=set(ports))
    return SimpleNamespace(rule=rule, permit=False, unmodelled=False, refs={}, leaves=leaves)


def _advise(access: list[Any], decryption: list[Any]) -> list[Any]:
    estate: Any = SimpleNamespace(asset_rows=SSL_ASSETS)
    advisor = SslAdvisor(estate)
    advisor.access(ACP, access)
    advisor.decryption_policy(SSL, decryption)
    return advisor._decrypt_inbound()


def test_resign_is_proposed_for_https_only() -> None:
    web = _access("10.20.0.0/24", ["TCP/443"], ("GOLD",))
    (draft,) = _advise([web], [])
    (new_rule,) = draft.preview["after"]
    assert new_rule["action"] == "DECRYPT_RESIGN"  # never known-key
    assert new_rule["fields"] == {"dst_net": ["SQL-FIN"], "dst_port": ["TCP/443"]}
    assert "Decrypt-Resign" in draft.title
    assert "HTTPS" in draft.title
    assert draft.warnings == ["resign_ca_trust", "resign_pinning_mtls", "resign_invalid_cert"]
    assert draft.plan["blocked"] == ["decryption_rule_manual"]
    # An application-based HTTPS rule counts; other TLS ports and protocols do not.
    assert _advise([_access("10.20.0.0/24", ["TCP/9999"], ("GOLD",), apps=("HTTPS",))], [])
    for ports in (["TCP/8443"], ["TCP/993"], ["TCP/636"], ["TCP/22"]):
        assert _advise([_access("10.20.0.0/24", ports, ("GOLD",))], []) == []


def test_one_rule_covers_gold_and_silver_systems_missing_it() -> None:
    gold = _access("10.20.0.0/24", ["TCP/443"], ("GOLD",))
    silver = _access("10.30.0.0/24", ["TCP/443"], ("SILVER",))
    (draft,) = _advise([gold, silver], [])
    assert draft.preview["systems"] == ["PORTAL", "SQL-FIN"]
    assert draft.priority == 65  # a GOLD system is in


def test_resign_is_never_proposed_for_core() -> None:
    dns = _access("10.40.0.0/24", ["TCP/443"], ("CORE",))
    assert _advise([dns], []) == []


def test_existing_decryption_settles_the_system() -> None:
    web = _access("10.20.0.0/24", ["TCP/443"], ("GOLD",))
    for action in ("DECRYPT_RESIGN", "DECRYPT_KNOWN_KEY"):
        assert _advise([web], [_decrypt(action, ["10.20.0.0/24"], ["TCP/443"])]) == []
        assert _advise([web], [_decrypt(action, ["10.20.0.0/24"], None)]) == []  # any port
    # Decrypting another port does not cover HTTPS.
    assert _advise([web], [_decrypt("DECRYPT_RESIGN", ["10.20.0.0/24"], ["TCP/8443"])])
    # Do-not-decrypt over the system is a deliberate exclusion: nothing to propose.
    assert _advise([web], [_decrypt("DO_NOT_DECRYPT", ["10.20.0.0/24"], ["TCP/443"])]) == []
    # ... unless a decrypt rule comes first for the same traffic, which also settles it.
    assert (
        _advise(
            [web],
            [
                _decrypt("DECRYPT_RESIGN", ["10.20.0.0/24"], ["TCP/443"]),
                _decrypt("DO_NOT_DECRYPT", ["10.20.0.0/24"], ["TCP/443"]),
            ],
        )
        == []
    )
