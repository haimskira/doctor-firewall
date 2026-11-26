"""Asset discovery end to end: suggestions, review, re-run, bulk delete, segments, domains."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.analysis.assets import effective_assets
from app.collector import runner
from app.db.session import get_sessionmaker
from app.fmc.client import ThrottlePolicy
from app.models.assets import Asset, AssetGroup, Segment
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import _snapshot


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("disc-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "disc-admin")}


def _count(model: type[Asset] | type[AssetGroup] | type[Segment]) -> int:
    with get_sessionmaker()() as s:
        return s.scalar(select(func.count()).select_from(model)) or 0


def test_discovery_suggests_reviews_and_reruns(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    # A leftover of the old per-address bootstrap: discovery replaces it.
    with get_sessionmaker().begin() as s:
        s.add(
            Asset(
                network="10.250.250.250/32",
                system="old",
                tier="SILVER",
                source="bootstrap",
                confirmed=False,
                updated_by="x",
            )
        )
    result = client.post("/api/assets/discover", headers=admin, json={"snapshot_id": sid})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["segments"] > 0
    assert body["assets"] > 0
    assert body["components"] > 0
    assert body["replaced"] >= 1
    assert _count(Asset) >= body["components"]
    with get_sessionmaker()() as s:
        assert s.scalar(select(Asset.id).where(Asset.network == "10.250.250.250/32")) is None
        # Suggestions do not feed the analysis until accepted.
        assert effective_assets(s) == []

    segments = client.get("/api/segments").json()
    gateways = [x for x in segments if x["gateway"]]
    assert gateways
    assert all(x["source"] == "discovery" and not x["confirmed"] for x in segments)
    assert any(x["role"] == "outside" for x in segments)
    assert all(x["evidence"] for x in gateways)

    groups = client.get("/api/asset-groups").json()
    pending = [g for g in groups if not g["confirmed"]]
    assert pending
    assert all(g["source"] == "discovery" and g["evidence"] for g in pending)

    one = pending[0]["id"]
    assert client.post("/api/asset-groups/confirm", headers=admin, json={"ids": [one]}).json() == {
        "confirmed": 1
    }
    with get_sessionmaker()() as s:
        assert effective_assets(s)  # the accepted asset counts now
    confirmed_all = client.post("/api/asset-groups/confirm", headers=admin, json={"all": True})
    assert confirmed_all.json()["confirmed"] == len(pending) - 1
    assert client.post("/api/asset-groups/confirm", headers=admin, json={}).status_code == 422

    # Re-running never touches what was accepted: everything is already classified.
    again = client.post("/api/assets/discover", headers=admin, json={"snapshot_id": sid}).json()
    assert again["assets"] == 0
    assert again["skipped"] > 0
    # The old endpoint still works (it runs discovery).
    assert (
        client.post("/api/assets/bootstrap", headers=admin, json={"snapshot_id": sid}).status_code
        == 200
    )


def test_purge_scopes_need_the_confirmation_word(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    client.post("/api/assets/discover", headers=admin, json={"snapshot_id": sid})
    client.post(
        "/api/assets",
        headers=admin,
        json={"network": "10.77.0.0/16", "system": "Stand-alone", "tier": "BRONZE"},
    )
    assert (
        client.post(
            "/api/assets/purge", headers=admin, json={"scope": "all", "confirm": "yes"}
        ).status_code
        == 422
    )
    unassigned = client.post(
        "/api/assets/purge", headers=admin, json={"scope": "unassigned", "confirm": "DELETE"}
    ).json()
    assert unassigned["deleted"] == 1
    suggested = client.post(
        "/api/assets/purge", headers=admin, json={"scope": "suggested", "confirm": "DELETE"}
    ).json()
    assert suggested["deleted"] > 0
    assert _count(AssetGroup) == 0
    client.post("/api/assets/discover", headers=admin, json={"snapshot_id": sid})
    client.post("/api/asset-groups/confirm", headers=admin, json={"all": True})
    everything = client.post(
        "/api/assets/purge", headers=admin, json={"scope": "all", "confirm": "DELETE"}
    ).json()
    assert everything["deleted"] > 0
    assert _count(Asset) == 0
    assert _count(AssetGroup) == 0


def _segment(client: TestClient, network: str) -> dict[str, object]:
    return next(x for x in client.get("/api/segments").json() if x["network"] == network)


def test_segments_and_domains_are_editable(client: TestClient, admin: dict[str, str]) -> None:
    created = client.post(
        "/api/segments",
        headers=admin,
        json={"network": "10.66.1.7/24", "name": "Floor 1", "role": "sda_users", "domain": "AH"},
    )
    assert created.status_code == 201, created.text
    seg = created.json()
    assert seg["network"] == "10.66.1.0/24"
    assert seg["confirmed"]
    assert seg["source"] == "manual"
    assert (
        client.post("/api/segments", headers=admin, json={"network": "10.66.1.0/24"}).status_code
        == 409
    )
    changed = client.patch(
        f"/api/segments/{seg['id']}", headers=admin, json={"role": "dc_servers"}
    ).json()
    assert changed["role"] == "dc_servers"
    assert changed["in_dc"] is True
    assert (
        client.patch(
            f"/api/segments/{seg['id']}", headers=admin, json={"role": "printers"}
        ).status_code
        == 422
    )

    domain = client.post("/api/asset-domains", headers=admin, json={"name": "ah"}).json()
    assert domain["name"] == "AH"
    assert domain["segments"] == 1
    renamed = client.patch(
        f"/api/asset-domains/{domain['id']}", headers=admin, json={"name": "ah-corp"}
    ).json()
    assert renamed["name"] == "AH-CORP"
    assert renamed["segments"] == 1
    assert _segment(client, "10.66.1.0/24")["domain"] == "AH-CORP"
    assert client.delete(f"/api/asset-domains/{domain['id']}", headers=admin).status_code == 204
    assert _segment(client, "10.66.1.0/24")["domain"] is None

    client.post(
        "/api/segments/purge", headers=admin, json={"scope": "suggested", "confirm": "DELETE"}
    )
    assert _segment(client, "10.66.1.0/24")["source"] == "manual"  # not a suggestion: kept
    assert client.delete(f"/api/segments/{seg['id']}", headers=admin).status_code == 204


def test_readers_cannot_discover_or_purge(client: TestClient) -> None:
    make_user("disc-view", ["viewer"])
    h = {"X-CSRF-Token": login(client, "disc-view")}
    assert client.get("/api/segments").status_code == 200
    assert (
        client.post("/api/assets/discover", headers=h, json={"snapshot_id": 1}).status_code == 403
    )
    assert (
        client.post(
            "/api/assets/purge", headers=h, json={"scope": "all", "confirm": "DELETE"}
        ).status_code
        == 403
    )
    assert (
        client.post("/api/segments", headers=h, json={"network": "10.1.1.0/24"}).status_code == 403
    )
