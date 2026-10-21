"""Assets (systems, servers, users, segments) with their components."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import _snapshot


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("ag-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "ag-admin")}


def test_assets_with_components_drive_the_analysis(
    client: TestClient, admin: dict[str, str]
) -> None:
    made = client.post(
        "/api/asset-groups",
        headers=admin,
        json={"name": "FIN-CORE", "kind": "system", "tier": "SILVER", "owner": "Finance IT"},
    )
    assert made.status_code == 201, made.text
    gid = made.json()["id"]
    assert (
        client.post(
            "/api/asset-groups", headers=admin, json={"name": "FIN-CORE", "tier": "GOLD"}
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/asset-groups", headers=admin, json={"name": "X", "tier": "GOLD", "kind": "planet"}
        ).status_code
        == 422
    )

    db = client.post(
        f"/api/asset-groups/{gid}/components",
        headers=admin,
        json={"name": "SQL-FIN", "network": "10.20.5.7/24", "role": "DB", "ports": "TCP 1433"},
    )
    assert db.status_code == 201, db.text
    assert db.json()["network"] == "10.20.5.0/24"
    assert db.json()["tier"] == "SILVER"
    app = client.post(
        f"/api/asset-groups/{gid}/components",
        headers=admin,
        json={"name": "FIN-APP", "network": "10.30.0.0/16", "role": "App"},
    )
    assert app.status_code == 201
    dup = client.post(
        f"/api/asset-groups/{gid}/components",
        headers=admin,
        json={"name": "Y", "network": "10.30.0.0/16"},
    )
    assert dup.status_code == 409

    # Re-classifying the asset re-classifies its components.
    upd = client.patch(f"/api/asset-groups/{gid}", headers=admin, json={"tier": "GOLD"})
    assert upd.status_code == 200
    assert {c["tier"] for c in upd.json()["components"]} == {"GOLD"}

    # A stand-alone entry can be moved into the asset (it takes the asset's tier).
    lone = client.post(
        "/api/assets",
        headers=admin,
        json={"network": "10.40.0.0/16", "system": "DEV", "tier": "BRONZE"},
    ).json()
    moved = client.patch(f"/api/assets/{lone['id']}", headers=admin, json={"group_id": gid})
    assert (moved.json()["group_id"], moved.json()["tier"]) == (gid, "GOLD")
    out = client.patch(f"/api/assets/{lone['id']}", headers=admin, json={"group_id": None})
    assert out.json()["group_id"] is None

    groups = client.get("/api/asset-groups").json()
    fin = next(g for g in groups if g["name"] == "FIN-CORE")
    assert [c["system"] for c in fin["components"]] == ["SQL-FIN", "FIN-APP"]
    assert fin["owner"] == "Finance IT"

    # The analysis sees the asset: one map node "GOLD|FIN-CORE" for both components.
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    nodes = {n["id"]: n for n in client.get(f"/api/snapshots/{sid}/map?limit=5000").json()["nodes"]}
    assert "GOLD|FIN-CORE" in nodes
    assert set(nodes["GOLD|FIN-CORE"]["networks"]) == {"10.20.5.0/24", "10.30.0.0/16"}
    assert not any(n.endswith("|SQL-FIN") for n in nodes)

    make_user("ag-view", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "ag-view")}
        assert viewer.get("/api/asset-groups").status_code == 200
        assert (
            viewer.post(
                "/api/asset-groups", headers=h, json={"name": "Z", "tier": "GOLD"}
            ).status_code
            == 403
        )

    assert client.delete(f"/api/asset-groups/{gid}", headers=admin).status_code == 204
    remaining = {a["network"] for a in client.get("/api/assets").json()}
    assert remaining == {"10.40.0.0/16"}  # components went with their asset


def test_csv_with_asset_columns(client: TestClient, admin: dict[str, str]) -> None:
    csv = (
        "network,system,tier,system_type,ports,asset,asset_kind\n"
        "10.20.5.0/24,SQL-FIN,GOLD,DB,TCP 1433,FIN-CORE,system\n"
        "10.20.6.0/24,SQL-HR,GOLD,DB,TCP 1433,FIN-CORE,system\n"
        "10.100.10.0/24,FIN-USERS,USERS,,,FIN-STAFF,user_segment\n"
        "10.0.0.53,DNS,CORE,Infra,UDP 53,,\n"
    )
    result = client.post("/api/assets/import", headers=admin, json={"csv": csv})
    assert result.json() == {"created": 4, "updated": 0}
    groups = {g["name"]: g for g in client.get("/api/asset-groups").json()}
    assert len(groups["FIN-CORE"]["components"]) == 2
    assert groups["FIN-STAFF"]["kind"] == "user_segment"
    bad = client.post(
        "/api/assets/import",
        headers=admin,
        json={"csv": "network,system,tier,asset_kind\n10.9.9.9,X,GOLD,planet\n"},
    )
    assert bad.status_code == 422
    assert bad.json()["errors"] == [{"line": 2, "fields": ["asset_kind"]}]
    exported = client.get("/api/assets/export").text.splitlines()
    assert exported[0].endswith(",asset,asset_kind")
    assert any(line.endswith(",FIN-CORE,system") for line in exported)
    assert any(
        line.startswith("10.0.0.53/32,DNS,CORE") and line.endswith(",,") for line in exported
    )
