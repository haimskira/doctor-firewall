from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from fmc_mock.app import GLOBAL_DOMAIN_UUID, create_app
from fmc_mock.auth import TokenStore
from fmc_mock.seed import generate

BASE = f"/api/fmc_config/v1/domain/{GLOBAL_DOMAIN_UUID}"


@pytest.fixture
def client() -> TestClient:
    store = TokenStore(username="u", password="p")
    c = TestClient(create_app(store=store, data=generate(clusters=2, rules_per_policy=60)))
    auth = "Basic " + base64.b64encode(b"u:p").decode()
    token = c.post(
        "/api/fmc_platform/v1/auth/generatetoken", headers={"Authorization": auth}
    ).headers["X-auth-access-token"]
    c.headers["X-auth-access-token"] = token
    return c


def test_paging_and_expanded(client: TestClient) -> None:
    first = client.get(f"{BASE}/object/hosts?limit=5").json()
    assert len(first["items"]) == 5
    assert set(first["items"][0]) == {"id", "name", "type", "links"}
    assert first["paging"]["offset"] == 0
    assert "next" in first["paging"]
    total = first["paging"]["count"]
    full = client.get(f"{BASE}/object/hosts?limit=1000&expanded=true").json()
    assert len(full["items"]) == total
    assert "value" in full["items"][0]
    assert "next" not in full["paging"]


def test_empty_collection_omits_items(client: TestClient) -> None:
    body = client.get(f"{BASE}/object/urlgroups").json()
    assert "items" not in body
    assert body["paging"]["count"] == 0


@pytest.mark.parametrize("query", ["limit=1001", "limit=0", "offset=-1", "limit=abc"])
def test_invalid_paging(client: TestClient, query: str) -> None:
    assert client.get(f"{BASE}/object/hosts?{query}").status_code == 400


def test_auth_and_domain_enforced(client: TestClient) -> None:
    assert (
        client.get(f"{BASE}/object/hosts", headers={"X-auth-access-token": "nope"}).status_code
        == 401
    )
    assert client.get("/api/fmc_config/v1/domain/other/object/hosts").status_code == 404


def test_rules_are_ordered_with_sections_and_categories(client: TestClient) -> None:
    policy = client.get(f"{BASE}/policy/accesspolicies?expanded=true").json()["items"][0]
    rules = client.get(
        f"{BASE}/policy/accesspolicies/{policy['id']}/accessrules?expanded=true&limit=1000"
    ).json()["items"]
    indexes = [r["metadata"]["ruleIndex"] for r in rules]
    assert indexes == list(range(1, len(rules) + 1))
    sections = [r["metadata"]["section"] for r in rules]
    assert sections == sorted(sections, key=lambda s: s != "Mandatory")
    assert client.get(f"{BASE}/policy/accesspolicies/nope/accessrules").status_code == 404


def test_hitcounts_require_device_filter(client: TestClient) -> None:
    policy = client.get(f"{BASE}/policy/accesspolicies").json()["items"][0]
    url = f"{BASE}/policy/accesspolicies/{policy['id']}/operational/hitcounts"
    assert client.get(url).status_code == 400
    device = client.get(f"{BASE}/devices/devicerecords?expanded=true").json()["items"][0]
    ok = client.get(url, params={"filter": f'"deviceId:{device["id"]}"', "expanded": "true"})
    assert ok.status_code == 200
    assert "hitCount" in ok.json()["items"][0]


def test_device_subresources(client: TestClient) -> None:
    pairs = client.get(f"{BASE}/devicehapairs/ftddevicehapairs?expanded=true").json()["items"]
    primary = pairs[0]["primary"]["id"]
    ifaces = client.get(
        f"{BASE}/devices/devicerecords/{primary}/physicalinterfaces?expanded=true"
    ).json()["items"]
    assert {i["ifname"] for i in ifaces} >= {"inside", "outside"}
    routes = client.get(
        f"{BASE}/devices/devicerecords/{primary}/routing/ipv4staticroutes?expanded=true"
    ).json()["items"]
    assert any("literal" in r["gateway"] for r in routes)
    assert client.get(f"{BASE}/devices/devicerecords/nope/physicalinterfaces").status_code == 404


def test_generator_is_deterministic_and_messy() -> None:
    a, b = (
        generate(clusters=1, rules_per_policy=80, seed=7),
        generate(clusters=1, rules_per_policy=80, seed=7),
    )
    assert a.rules == b.rules
    hosts = a.objects["hosts"]
    values = [h["value"] for h in hosts]
    assert len(values) != len(set(values))  # duplicate objects present
    names = {g["name"] for g in a.objects["networkgroups"]}
    assert {"GRP_LOOP_A", "GRP_LOOP_B", "GRP_NEST_1", "GRP_UNUSED"} <= names
    rules = next(iter(a.rules.values()))
    assert any(r["name"] == "ANY_ANY_TEMP" for r in rules)
    assert any(r.get("enabled") is False for r in rules)


def test_policy_dependencies(client: TestClient) -> None:
    acp = client.get(f"{BASE}/policy/accesspolicies?expanded=true").json()["items"][0]
    prefilter_ref = acp["prefilterPolicySetting"]
    prefilters = client.get(f"{BASE}/policy/prefilterpolicies?expanded=true").json()["items"]
    assert prefilter_ref["id"] in {p["id"] for p in prefilters}
    rules = client.get(
        f"{BASE}/policy/prefilterpolicies/{prefilter_ref['id']}/prefilterrules?expanded=true"
    ).json()["items"]
    assert {r["action"] for r in rules} == {"BLOCK", "FASTPATH", "ANALYZE"}
    nat = client.get(f"{BASE}/policy/ftdnatpolicies").json()["items"][0]
    auto = client.get(f"{BASE}/policy/ftdnatpolicies/{nat['id']}/autonatrules?expanded=true")
    assert auto.json()["items"][0]["natType"] == "STATIC"
    assignments = client.get(f"{BASE}/assignment/policyassignments?expanded=true").json()["items"]
    assert {a["policy"]["type"] for a in assignments} == {"AccessPolicy", "FTDNatPolicy"}
    for resource in (
        "decryptionpolicies",
        "identitypolicies",
        "intrusionpolicies",
        "filepolicies",
        "dnspolicies",
    ):
        assert client.get(f"{BASE}/policy/{resource}").json()["paging"]["count"] >= 1
    assert client.get(f"{BASE}/policy/ftdnatpolicies/nope/autonatrules").status_code == 404
