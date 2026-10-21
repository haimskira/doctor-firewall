"""Phase 6: inspection by destination tier — IPS / file policy and SSL decryption."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.fmc.errors import FmcWriteRejectedError
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import _snapshot
from tests.integration.test_phase3 import _all
from tests.integration.test_phase5_writes import (  # _fresh_mock: autouse, resets the mock
    CONFIG,
    Flow,
    _fresh_mock,
    _run,
    mock,
)

__all__ = ["_fresh_mock"]

NTP_CSV = "network,system,tier\n10.0.0.123,NTP,CORE\n"


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("p6-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "p6-admin")}


def _detail(rec: dict[str, Any], client: TestClient, sid: int) -> dict[str, Any]:
    detail: dict[str, Any] = client.get(f"/api/snapshots/{sid}/recommendations/{rec['id']}").json()
    return detail


def _ops(rec: dict[str, Any], client: TestClient, sid: int) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = _detail(rec, client, sid)["plan"]["ops"]
    return ops


def test_inspection_follows_the_destination_tier(client: TestClient, admin: dict[str, str]) -> None:
    client.post("/api/assets/import", headers=admin, json={"csv": NTP_CSV})
    flow = Flow(client, admin)  # imports the doctrine assets, pulls and analyses
    recs = _all(client, flow.sid, kind="add_inspection")
    assert recs, "rules to GOLD / SILVER without inspection must be found"

    # GOLD without any intrusion policy: Maximum Detection, executable.
    gold = [r for r in recs if "IPS Maximum Detection" in r["title"] and r["executable"]]
    assert gold
    assert gold[0]["title"].endswith("+ file policy (not configured)")
    assert "file_profile_not_configured" in gold[0]["warnings"]
    (op,) = _ops(gold[0], client, flow.sid)
    assert op["op"] == "set_inspection"
    assert op["ips"]["name"] == "Maximum Detection"
    assert "file" not in op  # no file policy configured for GOLD yet

    # Already Maximum Detection but no file policy: a to-do until a file profile exists.
    dba = flow.find("add_inspection", "DBA-PAW_TO_GOLD-DB_ADMIN")
    assert dba["executable"] is False
    assert dba["blocked"] == ["file_profile_not_configured"]
    assert not any(
        t["name"] == "FIN-APP_TO_GOLD-DB_SQL" for r in recs for t in r["targets"]
    )  # IPS Maximum Detection + file policy: compliant

    # SSL: NTP (CORE) is decrypted by the users' resign rule; DNS is exempt already.
    (core_row,) = _all(client, flow.sid, kind="ssl_exempt_core")
    core = _detail(core_row, client, flow.sid)
    assert core["preview"]["systems"] == ["NTP"]
    assert core["executable"] is False
    assert core["blocked"] == ["decryption_rule_manual"]
    assert core["preview"]["after"][0]["action"] == "DO_NOT_DECRYPT"
    # SQL-FIN (GOLD) has its known-key rule; no inbound proposal for GOLD.
    inbound = _all(client, flow.sid, kind="ssl_decrypt_inbound")
    assert not any("GOLD system" in r["title"] for r in inbound)

    # Configure the GOLD file policy and re-analyse: the DBA rule becomes executable.
    catalog = client.get("/api/inspection-profiles").json()
    assert {p["name"] for p in catalog["file_policies"]} == {"Block Malware"}
    levels = {p["name"]: p["level"] for p in catalog["intrusion_policies"]}
    assert levels == {"Balanced Security and Connectivity": 2, "Maximum Detection": 4}
    gold_profile = next(p for p in catalog["profiles"] if p["tier"] == "GOLD")
    assert (gold_profile["ips_policy"], gold_profile["configured"]) == ("Maximum Detection", False)
    ok = client.put(
        "/api/inspection-profiles/GOLD",
        headers=admin,
        json={"ips_policy": "Maximum Detection", "file_policy": "Block Malware"},
    )
    assert ok.status_code == 204
    jobs.analyze_snapshot(flow.sid)
    dba = flow.find("add_inspection", "DBA-PAW_TO_GOLD-DB_ADMIN")
    assert dba["executable"] is True
    (op,) = _ops(dba, client, flow.sid)
    assert op["file"]["name"] == "Block Malware"
    assert "ips" not in op

    # Execute both through the normal approval flow and read the FMC back.
    target = next(
        r
        for r in _all(client, flow.sid, kind="add_inspection")
        if r["executable"] and "IPS Maximum Detection" in r["title"]
    )
    gold_rule = next(t["name"] for t in target["targets"])
    _cs, batch_id = flow.approved_batch([dba, target])
    result = _run(batch_id)
    assert result["ok"] is True, result
    rules = flow.rules(dba["policy_fmc_id"])
    assert rules["DBA-PAW_TO_GOLD-DB_ADMIN"]["filePolicy"]["name"] == "Block Malware"
    written = flow.rules(target["policy_fmc_id"])[gold_rule]
    assert written["ipsPolicy"]["name"] == "Maximum Detection"
    assert written["filePolicy"]["name"] == "Block Malware"
    variable_sets = mock("GET", CONFIG + "/object/variablesets")["items"]
    assert written["variableSet"]["id"] == variable_sets[0]["id"]
    flow.close()


def test_inspection_drift_and_profile_rbac(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)
    gold = next(
        r
        for r in _all(client, flow.sid, kind="add_inspection")
        if r["executable"] and "IPS Maximum Detection" in r["title"]
    )
    name = next(t["name"] for t in gold["targets"])
    _cs, batch_id = flow.approved_batch([gold])
    # Someone attaches another intrusion policy in the FMC after the snapshot.
    rule = flow.rules(gold["policy_fmc_id"])[name]
    balanced = next(
        p
        for p in mock("GET", CONFIG + "/policy/intrusionpolicies")["items"]
        if p["name"].startswith("Balanced")
    )
    variables = mock("GET", CONFIG + "/object/variablesets")["items"][0]
    body = {k: v for k, v in rule.items() if k not in ("links", "metadata")}
    body["action"] = "ALLOW"
    body["ipsPolicy"] = {"id": balanced["id"], "name": balanced["name"], "type": "IntrusionPolicy"}
    body["variableSet"] = {"id": variables["id"], "name": variables["name"], "type": "VariableSet"}
    path = CONFIG + f"/policy/accesspolicies/{gold['policy_fmc_id']}/accessrules/{rule['id']}"
    mock("PUT", path, body)
    result = _run(batch_id)
    assert result["ok"] is False
    assert result["error"] == "drift"
    assert flow.rules(gold["policy_fmc_id"])[name]["ipsPolicy"]["name"] == balanced["name"]

    # The FMC (mock) refuses an intrusion policy without a variable set or on a non-Allow rule.
    del body["variableSet"]
    with pytest.raises(FmcWriteRejectedError) as refused:
        mock("PUT", path, body)
    assert "variable set" in refused.value.description
    body["variableSet"] = {"id": variables["id"], "name": variables["name"], "type": "VariableSet"}
    body["action"] = "TRUST"
    with pytest.raises(FmcWriteRejectedError) as refused:
        mock("PUT", path, body)
    assert "Allow action" in refused.value.description

    make_user("p6-view", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "p6-view")}
        assert viewer.get("/api/inspection-profiles").status_code == 200
        assert (
            viewer.put(
                "/api/inspection-profiles/GOLD", headers=h, json={"ips_policy": "X"}
            ).status_code
            == 403
        )
    assert (
        client.put(
            "/api/inspection-profiles/CORE", headers=admin, json={"ips_policy": "X"}
        ).status_code
        == 422
    )
    assert client.delete("/api/inspection-profiles/SILVER", headers=admin).status_code == 404
    client.put("/api/inspection-profiles/SILVER", headers=admin, json={"ips_policy": "X"})
    assert client.delete("/api/inspection-profiles/SILVER", headers=admin).status_code == 204
    flow.close()


def test_no_asset_table_no_inspection_proposals(client: TestClient, admin: dict[str, str]) -> None:
    # Inspection follows the destination tier: without classified assets there is none.
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    assert _all(client, sid, kind="add_inspection") == []
    assert _all(client, sid, kind="ssl_exempt_core") == []
