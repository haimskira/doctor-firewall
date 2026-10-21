"""Configuration writes and deployment as the real FMC behaves (for the enforcement tests)."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from fastapi.testclient import TestClient

from fmc_mock.app import GLOBAL_DOMAIN_UUID, create_app
from fmc_mock.auth import TokenStore
from fmc_mock.seed import generate

BASE = f"/api/fmc_config/v1/domain/{GLOBAL_DOMAIN_UUID}"


@pytest.fixture
def client() -> TestClient:
    store = TokenStore(username="u", password="p")
    c = TestClient(create_app(store=store, data=generate(clusters=2, rules_per_policy=40)))
    auth = "Basic " + base64.b64encode(b"u:p").decode()
    token = c.post(
        "/api/fmc_platform/v1/auth/generatetoken", headers={"Authorization": auth}
    ).headers["X-auth-access-token"]
    c.headers["X-auth-access-token"] = token
    return c


def _by_name(client: TestClient, resource: str, name: str) -> dict[str, Any]:
    items = client.get(f"{BASE}/object/{resource}?limit=1000&expanded=true").json()["items"]
    found: dict[str, Any] = next(i for i in items if i["name"] == name)
    return found


def _policy_rules(client: TestClient) -> tuple[str, list[dict[str, Any]]]:
    policy = client.get(f"{BASE}/policy/accesspolicies?expanded=true").json()["items"][0]
    rules = client.get(
        f"{BASE}/policy/accesspolicies/{policy['id']}/accessrules?limit=1000&expanded=true"
    ).json()["items"]
    return policy["id"], rules


def test_object_lifecycle_and_safety(client: TestClient) -> None:
    made = client.post(
        f"{BASE}/object/hosts", json={"name": "H_NEW", "type": "Host", "value": "10.9.9.9"}
    )
    assert made.status_code == 201
    host = made.json()
    assert client.get(f"{BASE}/object/hosts/{host['id']}").json()["value"] == "10.9.9.9"
    # Duplicate names in the network name space (case-insensitive) are refused.
    dup = client.post(
        f"{BASE}/object/networks", json={"name": "h_new", "type": "Network", "value": "10.0.0.0/8"}
    )
    assert dup.status_code == 400
    assert "Duplicate name" in dup.json()["error"]["messages"][0]["description"]
    assert (
        client.post(f"{BASE}/object/hosts", json={"name": "X", "type": "Network"}).status_code
        == 400
    )
    renamed = client.put(f"{BASE}/object/hosts/{host['id']}", json={**host, "name": "H_RENAMED"})
    assert renamed.json()["name"] == "H_RENAMED"
    assert (
        client.put(f"{BASE}/object/hosts/{host['id']}", json={**host, "id": "other"}).status_code
        == 400
    )
    # Groups must reference existing objects.
    bad_group = client.post(
        f"{BASE}/object/networkgroups",
        json={
            "name": "GRP_BAD",
            "type": "NetworkGroup",
            "objects": [{"id": "nope", "type": "Host"}],
        },
    )
    assert bad_group.status_code == 400
    group = client.post(
        f"{BASE}/object/networkgroups",
        json={
            "name": "GRP_NEW",
            "type": "NetworkGroup",
            "objects": [{"id": host["id"], "type": "Host"}],
        },
    ).json()
    # An object in use cannot be deleted; once unused it can.
    in_use = client.delete(f"{BASE}/object/hosts/{host['id']}")
    assert in_use.status_code == 400
    assert "in use" in in_use.json()["error"]["messages"][0]["description"]
    assert client.delete(f"{BASE}/object/networkgroups/{group['id']}").status_code == 200
    assert client.delete(f"{BASE}/object/hosts/{host['id']}").status_code == 200
    assert client.get(f"{BASE}/object/hosts/{host['id']}").status_code == 404
    # Objects used by rules are protected too.
    gold = _by_name(client, "networkgroups", "GRP_SRV_GOLD")
    assert client.delete(f"{BASE}/object/networkgroups/{gold['id']}").status_code == 400


def test_rule_insert_update_delete_and_renumbering(client: TestClient) -> None:
    policy_id, rules = _policy_rules(client)
    base = f"{BASE}/policy/accesspolicies/{policy_id}/accessrules"
    source = rules[2]
    body = {k: v for k, v in source.items() if k not in ("id", "links", "metadata")}
    body["name"] = "INSERTED"
    made = client.post(f"{base}?insertAfter=3&section=mandatory", json=body)
    assert made.status_code == 201, made.text
    inserted = made.json()
    assert inserted["metadata"]["ruleIndex"] == 4
    assert inserted["metadata"]["section"] == "Mandatory"
    _, after = _policy_rules(client)
    assert [r["metadata"]["ruleIndex"] for r in after] == list(range(1, len(rules) + 2))
    assert after[3]["name"] == "INSERTED"
    assert client.post(f"{base}?insertAfter=3", json=body).status_code == 400  # duplicate name
    changed = client.put(f"{base}/{inserted['id']}", json={**inserted, "name": "INSERTED_2"})
    assert changed.json()["name"] == "INSERTED_2"
    assert changed.json()["metadata"]["ruleIndex"] == 4
    bogus = {**inserted, "destinationNetworks": {"objects": [{"id": "missing", "type": "Network"}]}}
    assert client.put(f"{base}/{inserted['id']}", json=bogus).status_code == 400
    assert client.delete(f"{base}/{inserted['id']}").status_code == 200
    _, final = _policy_rules(client)
    assert [r["id"] for r in final] == [r["id"] for r in rules]
    assert client.get(f"{base}/{inserted['id']}").status_code == 404


def test_deploy_task_and_faults(client: TestClient) -> None:
    assert "items" not in client.get(f"{BASE}/deployment/deployabledevices?expanded=true").json()
    policy_id, rules = _policy_rules(client)
    rule = rules[0]
    client.put(
        f"{BASE}/policy/accesspolicies/{policy_id}/accessrules/{rule['id']}",
        json={**rule, "name": "CHANGED"},
    )
    devices = client.get(f"{BASE}/deployment/deployabledevices?expanded=true").json()["items"]
    assert len(devices) == 1  # only the HA pair using this policy
    request = {
        "type": "DeploymentRequest",
        "version": devices[0]["version"],
        "forceDeploy": False,
        "ignoreWarning": True,
        "deviceList": [devices[0]["device"]["id"]],
    }
    task = client.post(f"{BASE}/deployment/deploymentrequests", json=request)
    assert task.status_code == 202
    task_id = task.json()["metadata"]["task"]["id"]
    states = [client.get(f"{BASE}/job/taskstatuses/{task_id}").json()["status"] for _ in range(3)]
    assert states == ["Deploying", "Deployed", "Deployed"]
    assert client.post(f"{BASE}/deployment/deploymentrequests", json=request).status_code == 400

    faults = client.post(
        "/mock/faults", json={"deploy_fail": True, "fail_write_on": "BOOM", "x": 1}
    )
    assert faults.json()["faults"] == {"deploy_fail": True, "fail_write_on": "BOOM"}
    rejected = client.put(
        f"{BASE}/policy/accesspolicies/{policy_id}/accessrules/{rule['id']}",
        json={**rule, "name": "BOOM-1"},
    )
    assert rejected.status_code == 400
    client.put(
        f"{BASE}/policy/accesspolicies/{policy_id}/accessrules/{rule['id']}",
        json={**rule, "name": "CHANGED-AGAIN"},
    )
    devices = client.get(f"{BASE}/deployment/deployabledevices?expanded=true").json()["items"]
    task_id = client.post(
        f"{BASE}/deployment/deploymentrequests",
        json={**request, "deviceList": [devices[0]["device"]["id"]]},
    ).json()["metadata"]["task"]["id"]
    client.get(f"{BASE}/job/taskstatuses/{task_id}")
    assert client.get(f"{BASE}/job/taskstatuses/{task_id}").json()["status"] == "Failed"

    assert client.post("/mock/reset").status_code == 204
    assert client.post("/mock/reset", headers={"X-auth-access-token": "nope"}).status_code == 401
    _, fresh = _policy_rules(client)
    assert fresh[0]["name"] == rule["name"]
