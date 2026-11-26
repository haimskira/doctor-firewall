"""Phase 6: one organisation profile; IPS and file policy are separate recommendations."""

from __future__ import annotations

from collections import Counter
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import get_sessionmaker
from app.fmc.errors import FmcWriteRejectedError
from app.models.inventory import Rule
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


def _configure(
    client: TestClient,
    admin: dict[str, str],
    sid: int,
    ips: str | None = "Maximum Detection",
    file: str | None = "Block Malware",
) -> None:
    """Choose the organisation's policies and analyse again."""
    done = client.put(
        "/api/inspection-profile", headers=admin, json={"ips_policy": ips, "file_policy": file}
    )
    assert done.status_code == 204
    jobs.analyze_snapshot(sid)


def _rule_names(recs: list[dict[str, Any]]) -> set[str]:
    return {t["name"] for r in recs for t in r["targets"]}


def test_one_profile_defaults_to_the_most_used_policy(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    catalog = client.get("/api/inspection-profile").json()
    assert set(catalog) == {"profile", "intrusion_policies", "file_policies", "snapshot_id"}
    profile = catalog["profile"]
    assert profile["configured"] is False
    assert profile["ips_default"] is True
    assert profile["file_default"] is True
    with get_sessionmaker()() as s:
        counts = Counter(
            s.scalars(
                select(Rule.ips_policy).where(
                    Rule.snapshot_id == flow.sid,
                    Rule.policy_kind == "access",
                    Rule.enabled.is_(True),
                    Rule.action == "ALLOW",
                    Rule.ips_policy.is_not(None),
                )
            )
        )
    best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    assert profile["ips_policy"] == best
    assert profile["file_policy"] == "Block Malware"
    assert {p["name"] for p in catalog["file_policies"]} == {"Block Malware"}
    levels = {p["name"]: p["level"] for p in catalog["intrusion_policies"]}
    assert levels == {"Balanced Security and Connectivity": 2, "Maximum Detection": 4}

    # The default drives the recommendations without anything saved.
    for rec in _all(client, flow.sid, kind="add_inspection"):
        if rec["executable"]:
            assert best in rec["title"]

    # Saving a choice wins over the default; deleting it goes back.
    other = (
        "Maximum Detection" if best != "Maximum Detection" else "Balanced Security and Connectivity"
    )
    assert (
        client.put(
            "/api/inspection-profile",
            headers=admin,
            json={"ips_policy": other, "file_policy": None},
        ).status_code
        == 204
    )
    saved = client.get("/api/inspection-profile").json()["profile"]
    assert (saved["ips_policy"], saved["ips_default"], saved["configured"]) == (other, False, True)
    assert (saved["file_policy"], saved["file_default"]) == ("Block Malware", True)
    assert client.delete("/api/inspection-profile", headers=admin).status_code == 204
    assert client.get("/api/inspection-profile").json()["profile"]["ips_policy"] == best
    flow.close()


def test_ips_and_file_policy_are_separate_recommendations(
    client: TestClient, admin: dict[str, str]
) -> None:
    client.post("/api/assets/import", headers=admin, json={"csv": NTP_CSV})
    flow = Flow(client, admin)  # imports the doctrine assets, pulls and analyses
    _configure(client, admin, flow.sid)
    ips_recs = _all(client, flow.sid, kind="add_inspection")
    file_recs = _all(client, flow.sid, kind="add_file_policy")
    assert ips_recs
    assert file_recs

    # IPS: the organisation's intrusion policy only — never a file policy in the same proposal.
    for rec in ips_recs:
        assert "file policy" not in rec["title"]
        assert rec["executable"] is True, rec["blocked"]
        (op,) = _ops(rec, client, flow.sid)
        assert op["op"] == "set_inspection"
        assert "file" not in op
        assert op["ips"]["name"] == "Maximum Detection"
        assert set(op["expect"]) == {"name", "action", "ips"}
    # File: the organisation's file policy only, on GOLD / SILVER destinations.
    for rec in file_recs:
        assert rec["title"].startswith("Attach file policy Block Malware to ")
        assert rec["executable"] is True, rec["blocked"]
        (op,) = _ops(rec, client, flow.sid)
        assert op["file"]["name"] == "Block Malware"
        assert "ips" not in op
        assert "action" not in op
        assert set(op["expect"]) == {"name", "file"}
        assert _detail(rec, client, flow.sid)["preview"]["tier"] in ("GOLD", "SILVER")

    # A rule with Maximum Detection and no file policy gets only the file proposal; a compliant
    # rule gets none.
    assert "DBA-PAW_TO_GOLD-DB_ADMIN" in _rule_names(file_recs)
    assert "DBA-PAW_TO_GOLD-DB_ADMIN" not in _rule_names(ips_recs)
    assert "FIN-APP_TO_GOLD-DB_SQL" not in _rule_names(ips_recs + file_recs)

    # A rule carrying another intrusion policy is switched to the organisation's.
    switches = [r for r in ips_recs if r["title"].startswith("Switch ")]
    assert switches
    for rec in switches:
        assert "to the organisation's intrusion policy Maximum Detection" in rec["title"]
        assert "(now Balanced Security and Connectivity)" in rec["title"]
        (op,) = _ops(rec, client, flow.sid)
        assert op["expect"]["ips"] is not None

    # SSL: NTP (CORE) is decrypted by the users' resign rule; DNS is exempt already.
    (core_row,) = _all(client, flow.sid, kind="ssl_exempt_core")
    core = _detail(core_row, client, flow.sid)
    assert core["preview"]["systems"] == ["NTP"]
    assert core["executable"] is False
    assert core["blocked"] == ["decryption_rule_manual"]
    assert core["preview"]["after"][0]["action"] == "DO_NOT_DECRYPT"
    assert core["preview"]["after"][0]["name"] == "DND_CORE_SERVICES"
    assert "FMC-FTD sftunnel TCP-8305" in core["preview"]["services"]
    # Decryption proposals are Decrypt-Resign on HTTPS, never known-key; GOLD already has its
    # decrypt rule on 443 in the mock, so no proposal names a GOLD-only exposure it covers.
    for row in _all(client, flow.sid, kind="ssl_decrypt_inbound"):
        detail = _detail(row, client, flow.sid)
        (new_rule,) = detail["preview"]["after"]
        assert new_rule["action"] == "DECRYPT_RESIGN"
        assert new_rule["fields"]["dst_port"] == ["TCP/443"]
        assert "Decrypt-Resign" in row["title"]
        assert "known" not in row["title"].lower()
        assert detail["blocked"] == ["decryption_rule_manual"]
        assert "resign_ca_trust" in detail["warnings"]
        assert "server_cert_import_required" not in detail["warnings"]

    # Both proposals for one rule are staged in ONE changeset and run one after the other: the
    # file op does not trip over the intrusion-policy op that changed the same rule first.
    both = sorted(_rule_names(ips_recs) & _rule_names(file_recs))[0]
    ips = next(r for r in ips_recs if both in _rule_names([r]))
    file = next(r for r in file_recs if both in _rule_names([r]))
    assert ips["policy_fmc_id"] == file["policy_fmc_id"]
    _cs, batch_id = flow.approved_batch([ips, file])
    result = _run(batch_id)
    assert result["ok"] is True, result
    assert result["operations"] == 2  # one intrusion-policy op, one file-policy op
    written = flow.rules(ips["policy_fmc_id"])[both]
    assert written["ipsPolicy"]["name"] == "Maximum Detection"
    assert written["filePolicy"]["name"] == "Block Malware"
    variable_sets = mock("GET", CONFIG + "/object/variablesets")["items"]
    assert written["variableSet"]["id"] == variable_sets[0]["id"]
    flow.close()


def test_unusable_organisation_policy_blocks_the_proposals(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    _configure(client, admin, flow.sid, ips="No Such IPS", file="No Such File")
    ips_recs = _all(client, flow.sid, kind="add_inspection")
    file_recs = _all(client, flow.sid, kind="add_file_policy")
    assert ips_recs
    assert file_recs
    assert all(
        r["executable"] is False and r["blocked"] == ["ips_profile_missing"] for r in ips_recs
    )
    assert all(
        r["executable"] is False and r["blocked"] == ["file_profile_missing"] for r in file_recs
    )
    flow.close()


def test_inspection_drift_and_profile_rbac(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)
    _configure(client, admin, flow.sid)
    gold = next(
        r
        for r in _all(client, flow.sid, kind="add_inspection")
        if r["executable"] and r["title"].startswith("Attach the organisation's intrusion policy")
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
        assert viewer.get("/api/inspection-profile").status_code == 200
        assert (
            viewer.put("/api/inspection-profile", headers=h, json={"ips_policy": "X"}).status_code
            == 403
        )
    # One profile for the organisation: no tier in the body.
    assert (
        client.put(
            "/api/inspection-profile", headers=admin, json={"tier": "GOLD", "ips_policy": "X"}
        ).status_code
        == 422
    )
    client.delete("/api/inspection-profile", headers=admin)  # _configure saved one
    assert client.delete("/api/inspection-profile", headers=admin).status_code == 404
    flow.close()


def test_no_asset_table_no_inspection_proposals(client: TestClient, admin: dict[str, str]) -> None:
    # Inspection follows the destination tier: without classified assets there is none.
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    assert _all(client, sid, kind="add_inspection") == []
    assert _all(client, sid, kind="fastpath_candidate") == []  # DC ends need assets
    # Identity / management services are recognised by port, with or without assets.
    (row,) = _all(client, sid, kind="ssl_exempt_core")
    detail = client.get(f"/api/snapshots/{sid}/recommendations/{row['id']}").json()
    assert detail["preview"]["systems"] == []
    assert "LDAPS TCP-636" in detail["preview"]["services"]
    assert detail["preview"]["after"][0]["name"] == "DND_IDENTITY_MGMT_SERVICES"


def test_storage_between_dc_systems_is_a_fastpath_candidate_not_an_ips_one(
    client: TestClient, admin: dict[str, str]
) -> None:
    policy = mock("GET", CONFIG + "/policy/accesspolicies")["items"][0]
    rules = CONFIG + f"/policy/accesspolicies/{policy['id']}/accessrules"
    mock(
        "POST",
        rules + "?insertBefore=1",
        {
            "type": "AccessRule",
            "name": "APPS_TO_SQL_ISCSI",
            "enabled": True,
            "action": "ALLOW",
            "sourceNetworks": {"literals": [{"type": "Network", "value": "10.30.1.0/24"}]},
            "destinationNetworks": {"literals": [{"type": "Host", "value": "10.20.5.10"}]},
            "destinationPorts": {
                "literals": [{"type": "PortLiteral", "protocol": "6", "port": "3260"}]
            },
        },
    )
    flow = Flow(client, admin)
    rec = flow.find("fastpath_candidate", "APPS_TO_SQL_ISCSI")
    detail = _detail(rec, client, flow.sid)
    assert detail["executable"] is False
    assert detail["blocked"] == ["fastpath_manual"]
    assert detail["warnings"] == ["fastpath_no_inspection"]
    assert detail["preview"]["classes"] == ["storage"]
    assert detail["preview"]["after"][0]["action"] == "TRUST"
    # GOLD destination, no IPS — and still no add_inspection: the exemption wins.
    assert not any(
        t["name"] == "APPS_TO_SQL_ISCSI"
        for r in _all(client, flow.sid, kind="add_inspection")
        for t in r["targets"]
    )
    flow.close()
