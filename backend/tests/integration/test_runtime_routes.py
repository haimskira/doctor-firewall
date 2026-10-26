"""B-001: the runtime routing table (``show route`` through the FMC) and IP -> zone lookup."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import _snapshot
from tests.integration.test_phase5_writes import _fresh_mock, mock

__all__ = ["_fresh_mock"]


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("rr-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "rr-admin")}


def _clusters(client: TestClient, sid: int) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = client.get(f"/api/snapshots/{sid}/clusters").json()
    return clusters


def test_dynamic_routes_are_collected_and_resolve_ips(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _snapshot(client, admin)
    cluster = _clusters(client, sid)[0]
    network = client.get(f"/api/snapshots/{sid}/clusters/{cluster['fmc_id']}/network").json()
    assert network["runtime"]["status"] == "ok"
    dynamic = [r for r in network["routes"] if r["kind"] == "dynamic"]
    assert sorted({r["protocol"] for r in dynamic}) == ["bgp", "eigrp EX", "ospf E2", "ospf IA"]
    assert network["runtime"]["routes"] == len(dynamic) == 6  # 2 BGP, 2 OSPF IA paths, E2, EX
    bgp = next(r for r in dynamic if r["network"] == "10.50.0.0/16")
    assert (bgp["interface"], bgp["distance"]) == ("outside", 20)

    def lookup(ip: str) -> dict[str, Any]:
        found: dict[str, Any] = client.get(
            f"/api/snapshots/{sid}/clusters/{cluster['fmc_id']}/route-lookup", params={"ip": ip}
        ).json()
        return found

    best = lookup("10.50.7.7")["best"]
    assert (best["kind"], best["protocol"], best["interface"], best["zone"]) == (
        "dynamic",
        "bgp",
        "outside",
        "outside",
    )
    inside = next(i for i in network["interfaces"] if i["ifname"] == "inside")
    octet = inside["ipv4"].split(".")[1]
    ospf = lookup(f"10.60.{octet}.20")
    assert (ospf["best"]["protocol"], ospf["best"]["zone"]) == ("ospf IA", "inside")
    assert len([m for m in ospf["matches"] if m["network"] == f"10.60.{octet}.0/24"]) == 2
    assert lookup("8.8.8.8")["best"]["network"] == "0.0.0.0/0"
    assert lookup(f"10.20.{octet}.9")["best"]["kind"] == "connected"
    assert (
        client.get(
            f"/api/snapshots/{sid}/clusters/{cluster['fmc_id']}/route-lookup",
            params={"ip": "10.0.0.300"},
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    ("fault", "status"),
    [("cli_unsupported", "unsupported"), ("device_down", "unavailable"), ("cli_mixup", "mismatch")],
)
def test_runtime_failures_never_fail_the_snapshot(
    client: TestClient, admin: dict[str, str], fault: str, status: str
) -> None:
    mock("POST", "/mock/faults", {fault: True})
    sid = _snapshot(client, admin)  # completes
    for cluster in _clusters(client, sid):
        network = client.get(f"/api/snapshots/{sid}/clusters/{cluster['fmc_id']}/network").json()
        assert network["runtime"]["status"] == status
        assert not [r for r in network["routes"] if r["kind"] == "dynamic"]
        # Configuration routes still answer lookups.
        assert {r["kind"] for r in network["routes"]} >= {"static", "connected"}
