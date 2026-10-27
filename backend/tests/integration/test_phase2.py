"""Phase 2 end-to-end: asset table, shadowing, dead rules, ACE limits, rule scores."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.collector import runner
from app.fmc.client import ThrottlePolicy
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_collection import _collect, _connection

DOCTRINE_CSV = """network,system,tier,system_type,user_type,ports,notes
10.20.5.0/24,SQL-FIN,GOLD,DB,,TCP 1433,crown jewels
10.30.0.0/16,APPS,SILVER,App,,,
10.40.0.0/16,DEV,BRONZE,App,,,
10.0.0.53,DNS,CORE,Infra,,UDP 53,
10.100.10.0/24,FIN-USERS,USERS,,FIN,,
10.100.20.0/24,IT-USERS,USERS,,IT,,
"""


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("p2-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "p2-admin")}


def _snapshot(client: TestClient, h: dict[str, str]) -> int:
    sid = _collect(client, h, _connection(client, h))
    assert jobs.collect_snapshot(sid)["ok"] is True
    return sid


def test_asset_crud_validation_and_rbac(client: TestClient, admin: dict[str, str]) -> None:
    created = client.post(
        "/api/assets",
        headers=admin,
        json={"network": "10.20.5.7/24", "system": "SQL-FIN", "tier": "GOLD", "system_type": "DB"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["network"] == "10.20.5.0/24"  # canonicalised
    assert body["confirmed"] is True
    assert (
        client.post(
            "/api/assets",
            headers=admin,
            json={"network": "10.20.5.0/24", "system": "x", "tier": "GOLD"},
        ).status_code
        == 409
    )
    for bad in (
        {"network": "not-an-ip", "system": "x", "tier": "GOLD"},
        {"network": "10.0.0.1", "system": "x", "tier": "PLATINUM"},
        {"network": "10.0.0.1", "system": "", "tier": "GOLD"},
        {"network": "10.0.0.1", "system": "x", "tier": "GOLD", "is_admin": True},
    ):
        assert client.post("/api/assets", headers=admin, json=bad).status_code == 422
    upd = client.patch(f"/api/assets/{body['id']}", headers=admin, json={"tier": "SILVER"})
    assert upd.json()["tier"] == "SILVER"
    make_user("p2-viewer", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "p2-viewer")}
        assert viewer.get("/api/assets").status_code == 200
        assert (
            viewer.post(
                "/api/assets",
                headers=h,
                json={"network": "10.9.9.9", "system": "x", "tier": "GOLD"},
            ).status_code
            == 403
        )
    assert client.delete(f"/api/assets/{body['id']}", headers=admin).status_code == 204
    assert client.get("/api/assets").json() == []


def test_csv_import_is_all_or_nothing_and_export_is_safe(
    client: TestClient, admin: dict[str, str]
) -> None:
    bad = "network,system,tier\n10.0.0.1,ok,GOLD\nnope,=cmd(),GOLD\n10.0.0.2,x,DIAMOND\n"
    resp = client.post("/api/assets/import", headers=admin, json={"csv": bad})
    assert resp.status_code == 422
    assert resp.json()["errors"] == [
        {"line": 3, "fields": ["network"]},
        {"line": 4, "fields": ["tier"]},
    ]
    assert "=cmd()" not in resp.text  # values are never echoed
    assert client.get("/api/assets").json() == []  # nothing was imported
    assert (
        client.post(
            "/api/assets/import", headers=admin, json={"csv": "system,tier\nx,GOLD\n"}
        ).status_code
        == 422
    )
    ok = client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV})
    assert ok.json() == {"created": 6, "updated": 0}
    again = client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV})
    assert again.json() == {"created": 0, "updated": 6}
    client.post(
        "/api/assets",
        headers=admin,
        json={"network": "10.77.0.0/16", "system": '=HYPERLINK("x")', "tier": "BRONZE"},
    )
    export = client.get("/api/assets/export")
    assert export.headers["content-type"].startswith("text/csv")
    assert "'=HYPERLINK" in export.text  # formula neutralised


def test_bootstrap_suggests_unconfirmed_assets(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    result = client.post("/api/assets/bootstrap", headers=admin, json={"snapshot_id": sid})
    assert result.json()["created"] > 0
    assets = {a["network"]: a for a in client.get("/api/assets").json()}
    assert all(a["confirmed"] is False and a["source"] == "bootstrap" for a in assets.values())
    assert assets["10.20.5.11/32"]["tier"] == "GOLD"  # H_GOLD_DB1
    assert assets["10.0.0.53/32"]["tier"] == "CORE"  # H_DNS1
    assert assets["10.100.10.0/24"]["tier"] == "USERS"
    assert assets["10.100.10.0/24"]["user_type"] == "FIN"
    assert "0.0.0.0/0" not in assets  # any-ipv4 is never suggested
    ids = [a["id"] for a in assets.values()]
    assert client.post("/api/assets/confirm", headers=admin, json={"ids": ids}).json()[
        "updated"
    ] == len(ids)
    assert (
        client.post("/api/assets/bootstrap", headers=admin, json={"snapshot_id": sid}).json()[
            "created"
        ]
        == 0
    )  # idempotent


def test_shadowing_dead_rules_and_scores(client: TestClient, admin: dict[str, str]) -> None:
    client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV})
    sid = _snapshot(client, admin)
    summary = jobs.analyze_snapshot(sid)
    assert summary.get("shadowed_rule", 0) > 0
    assert summary.get("dead_rule", 0) > 0

    shadowed = client.get(f"/api/snapshots/{sid}/findings?kind=shadowed_rule&limit=500").json()
    by_name = {f["details"]["rule"]["name"]: f for f in shadowed["rows"]}
    # Everything after ANY_ANY_TEMP is unreachable; a deny behind it is a conflict.
    assert by_name["NESTED_LOOP"]["details"]["by"]["name"] == "ANY_ANY_TEMP"
    assert by_name["NESTED_LOOP"]["severity"] == "medium"
    assert by_name["EXPLICIT_DEFAULT_DENY"]["severity"] == "high"
    assert by_name["EXPLICIT_DEFAULT_DENY"]["details"]["conflict"] is True

    clusters = client.get(f"/api/snapshots/{sid}/clusters").json()
    first = clusters[0]
    assert first["ace_total"] > 0
    assert first["ace_limit_verified"] is False
    policy = first["policy_fmc_id"]
    rows = {
        r["name"]: r
        for r in client.get(f"/api/snapshots/{sid}/policies/{policy}/rules?limit=500").json()[
            "rows"
        ]
    }
    good = rows["FIN-APP_TO_GOLD-DB_SQL"]
    assert good["dst_tiers"] == ["GOLD"]
    assert good["src_tiers"] == ["USERS"]
    assert good["score"] >= 80, good["reasons"]
    bad = rows["TEMP_DEV_TO_DB"]
    assert "tier_skip" in {r["code"] for r in bad["reasons"]}
    anyany = rows["ANY_ANY_TEMP"]
    assert {"any_destination", "any_source", "any_service"} <= {
        r["code"] for r in anyany["reasons"]
    }
    assert anyany["score"] <= 40
    assert rows["NESTED_LOOP"]["shadowed_by"] == anyany["id"]
    assert rows["EXPLICIT_DEFAULT_DENY"]["score"] is None  # deny rules are not scored

    queue = client.get(f"/api/snapshots/{sid}/scores?limit=50").json()
    scores = [q["score"] for q in queue]
    assert scores == sorted(scores)
    assert queue[0]["reasons"]


def test_cluster_ace_limit(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    cluster = client.get(f"/api/snapshots/{sid}/clusters").json()[0]
    limits = client.get(f"/api/clusters/{cluster['fmc_id']}/limits").json()
    assert limits["is_default"] is True
    put = client.put(
        f"/api/clusters/{cluster['fmc_id']}/limits",
        headers=admin,
        json={
            "ace_limit": 1000,
            "ace_limit_verified": True,
            "deploy_change_limit": 50,
            "deploy_limit_verified": False,
        },
    )
    assert put.status_code == 200
    jobs.analyze_snapshot(sid)
    findings = client.get(f"/api/snapshots/{sid}/findings?kind=ace_cluster_limit").json()
    hit = next(f for f in findings["rows"] if f["details"]["cluster"]["id"] == cluster["fmc_id"])
    assert hit["severity"] == "high"
    assert hit["details"]["limit_verified"] is True
    # The fix of an ACE budget: the recommendations that save the most ACEs, best first.
    recs = client.get(f"/api/snapshots/{sid}/recommendations?sort=ace_delta&order=asc&limit=5")
    best = [r["id"] for r in recs.json()["rows"] if r["ace_delta"] < 0]
    assert best
    assert [x["id"] for x in hit["fixes"]] == best
    make_user("p2-opt", ["optimizer"])
    with TestClient(client.app, base_url="https://testserver") as opt:
        h = {"X-CSRF-Token": login(opt, "p2-opt")}
        assert (
            opt.put(
                f"/api/clusters/{cluster['fmc_id']}/limits",
                headers=h,
                json={
                    "ace_limit": 5000,
                    "ace_limit_verified": True,
                    "deploy_change_limit": 5,
                    "deploy_limit_verified": True,
                },
            ).status_code
            == 403
        )
        assert (
            opt.post("/api/assets/import", headers=h, json={"csv": DOCTRINE_CSV}).status_code == 200
        )
