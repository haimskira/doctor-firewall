"""Attack surface API over a collected and analysed snapshot of the FMC mock."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _analysed


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("atk-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "atk-admin")}


def test_paths_to_a_target_and_blast_radius(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    base = f"/api/snapshots/{sid}/attack-surface"
    targets = client.get(f"{base}/targets").json()
    gold = [t for t in targets if t["tier"] == "GOLD"]
    users = [t for t in targets if t["tier"] == "USERS"]
    assert gold
    assert users

    results = [client.get(base, params={"system": t["id"], "depth": 3}) for t in gold]
    assert all(r.status_code == 200 for r in results)
    reached = [r.json() for r in results if r.json()["paths"]]
    assert reached, "some GOLD system must be reachable in the mock rulebase"
    surface = reached[0]
    assert surface["mode"] == "to"
    origin = set(surface["origin"]["nodes"])
    assert origin
    for path in surface["paths"]:
        assert set(path["steps"][-1]["nodes"]) & origin  # every path ends at the target
        assert len(path["hops"]) == len(path["steps"]) - 1
        assert all(h["rules"] for h in path["hops"])
    scores = [p["score"] for p in surface["paths"]]
    assert scores == sorted(scores, reverse=True)
    assert {n["id"] for n in surface["nodes"]} >= origin
    assert surface["summary"]["paths"] >= len(surface["paths"])

    blast = client.get(base, params={"system": users[0]["id"], "mode": "from", "depth": 2})
    assert blast.status_code == 200
    for path in blast.json()["paths"]:
        assert set(path["steps"][0]["nodes"]) & set(blast.json()["origin"]["nodes"])

    by_ip = client.get(base, params={"address": "10.20.0.10", "depth": 1})
    assert by_ip.status_code == 200
    assert by_ip.json()["origin"]["networks"] == ["10.20.0.10/32"]

    for params, code in (
        ({}, 422),
        ({"system": gold[0]["id"], "address": "10.0.0.1"}, 422),
        ({"address": "10.0.0.1/40"}, 422),
        ({"address": "0.0.0.0/0"}, 422),
        ({"system": "GOLD|no such system"}, 404),
        ({"object": "nope"}, 404),
        ({"system": gold[0]["id"], "depth": 9}, 422),
        ({"system": gold[0]["id"], "mode": "sideways"}, 422),
    ):
        assert client.get(base, params=params).status_code == code, params
    assert client.get("/api/snapshots/999999/attack-surface/targets").status_code == 404
