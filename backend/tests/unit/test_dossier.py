"""System dossier: peers on both sides, services as TCP-443, broad and internal rules."""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy.orm import Session

from app.analysis.assets import AssetRow
from app.analysis.attack import Hop
from app.analysis.dossier import build_dossier, port_labels
from app.analysis.space import AddressSet, PortSet

ROWS = [
    AssetRow("10.1.1.10/32", "DNA", "CORE", "App", None, "443", "DNAC-1"),
    AssetRow("10.1.1.11/32", "DNA", "CORE", "App", None, "443", "DNAC-2"),
    AssetRow("10.2.0.0/24", "ISE", "CORE", "App", None, "", "ISE"),
    AssetRow("10.50.0.0/16", "ENG-USERS", "USERS", "", "employees", "", "ENG-USERS"),
]
NO_DB = cast(Session, None)  # rule_id 0 hops never query their references


def hop(
    src: list[str] | None,
    dst: list[str] | None,
    ports: list[str] | None = None,
    *,
    name: str = "r",
    risk: str = "green",
    default: bool = False,
    hits: int | None = 5,
) -> Hop:
    return Hop(
        rule_id=0,
        fmc_id=name,
        name=name,
        index=1,
        policy_fmc_id="p1",
        policy_name="ACP",
        action="ALLOW",
        src=AddressSet(any=True) if src is None else AddressSet.build(src),
        dst=AddressSet(any=True) if dst is None else AddressSet.build(dst),
        services=("any",),
        apps=(),
        inspected=False,
        partial=False,
        risk=risk,
        hits=hits,
        default=default,
        ports=None if ports is None else PortSet.build(ports),
    )


def dossier(*hops: Hop) -> dict[str, Any]:
    return build_dossier(NO_DB, 1, list(hops), ROWS, "DNA", "CORE")


def peers(result: dict[str, Any], side: str) -> dict[str, dict[str, Any]]:
    return {p["key"]: p for p in result[side]}


def test_port_labels_read_like_the_fmc() -> None:
    assert port_labels(PortSet.build(["TCP/443"])) == ("TCP-443",)
    assert port_labels(PortSet.build(["UDP/53", "TCP/53"])) == ("TCP-53", "UDP-53")
    assert port_labels(PortSet.build(["TCP/8080-8090"])) == ("TCP-8080-8090",)
    assert port_labels(PortSet.build(["TCP/any"])) == ("TCP-any",)
    assert port_labels(PortSet(any=True)) == ("any",)
    assert port_labels(PortSet.build(["ICMP/8"])) == ("ICMP-8",)


def test_who_reaches_the_system_and_what_it_reaches() -> None:
    result = dossier(
        hop(["10.50.0.0/16"], ["10.1.1.10/32"], ["TCP/443"], name="users-to-dna"),
        hop(
            ["10.1.1.0/30", "10.1.1.10/31"],
            ["10.2.0.5/32"],
            ["TCP/49", "UDP/1812"],
            name="dna-to-ise",
        ),
    )
    inbound = peers(result, "inbound")
    users = inbound["sys:USERS|ENG-USERS"]
    assert users["kind"] == "system"
    assert users["services"] == ["TCP-443"]
    assert users["targets"] == ["DNAC-1"]
    assert (users["broad"], users["specific"]) == (0, 1)
    assert users["values"] == ["10.50.0.0/16"]
    outbound = peers(result, "outbound")
    assert set(outbound["sys:CORE|ISE"]["services"]) == {"TCP-49", "UDP-1812"}
    assert result["summary"]["inbound_rules"] == 1
    assert result["summary"]["outbound_rules"] == 1


def test_broad_any_default_and_internal_rules() -> None:
    result = dossier(
        hop(["10.50.0.0/16"], ["10.0.0.0/8"], ["TCP/22"], name="users-to-all", risk="yellow"),
        hop(None, ["10.1.1.11/32"], ["TCP/443"], name="any-to-dna", risk="red"),
        hop(None, None, None, name="default:p1", default=True, risk="red", hits=None),
        hop(["10.1.1.10/32"], ["10.1.1.11/32"], ["TCP/5432"], name="internal"),
    )
    inbound = peers(result, "inbound")
    broad = inbound["sys:USERS|ENG-USERS"]
    assert (broad["broad"], broad["specific"]) == (1, 0)  # written for 10/8, not for DNA
    assert broad["targets"] == ["DNAC-1", "DNAC-2"]
    assert inbound["any"]["risk"] == "red"
    assert inbound["default:p1"]["kind"] == "default"
    assert inbound["default:p1"]["hits"] is None
    assert "default:p1" in peers(result, "outbound")
    assert result["summary"]["internal_rules"] == 1
    assert all("internal" not in [r["name"] for r in p["rules"]] for p in result["inbound"])
    order = [p["kind"] for p in result["inbound"]]
    assert order == sorted(order, key=["system", "object", "network", "any", "default"].index)


def test_addresses_outside_the_asset_table_still_show() -> None:
    result = dossier(hop(["192.168.7.7/32"], ["10.1.1.10/32"], ["TCP/22", "TCP/3389"]))
    (peer,) = result["inbound"]
    assert peer["kind"] == "network"  # no named reference on a rule without refs
    assert peer["values"] == ["192.168.7.7/32"]
    assert peer["services"] == ["TCP-22", "TCP-3389"]


def test_unrelated_rules_are_ignored() -> None:
    result = dossier(hop(["10.50.0.0/16"], ["10.2.0.0/24"], ["TCP/443"]))
    assert (result["inbound"], result["outbound"]) == ([], [])
    assert result["components"][0]["name"] == "DNAC-1"
