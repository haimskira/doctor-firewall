"""Clean-up roadmap over an analysed snapshot of the FMC mock."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _analysed

PHASES = ["never_match", "objects", "structure", "access", "closing"]


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("road-admin", ["admin", "optimizer"])
    return {"X-CSRF-Token": login(client, "road-admin")}


def test_the_roadmap_orders_the_clean_up_and_moves_on(
    client: TestClient, admin: dict[str, str]
) -> None:
    sid = _analysed(client, admin)
    road = client.get(f"/api/snapshots/{sid}/roadmap").json()
    by = {p["name"]: p for p in road["phases"]}
    assert [p["name"] for p in road["phases"]] == PHASES
    # The mock has shadowed and disabled rules: the project starts there.
    assert road["current"] == "never_match"
    assert road["phases"][0]["status"] == "current"
    assert {p["status"] for p in road["phases"][1:]} <= {"next", "done"}
    assert by["access"]["behavior"] == "changes"
    assert {by[n]["behavior"] for n in PHASES if n != "access"} == {"preserves"}
    total = client.get(f"/api/snapshots/{sid}/recommendations?limit=1").json()["total"]
    assert sum(p["total"] for p in road["phases"]) == total
    checks = {c["code"]: c for c in road["prepare"]}
    assert checks["assets"]["ok"] is True
    assert checks["fresh"]["ok"] is True
    assert checks["limits"]["ok"] is False  # nobody verified the cluster limits yet

    # The recommendations list (and the bulk decision) take one phase.
    page = client.get(f"/api/snapshots/{sid}/recommendations?phase=never_match&limit=500").json()
    assert page["total"] == by["never_match"]["total"]
    assert {r["kind"] for r in page["rows"]} <= {"remove_disabled_rule", "remove_shadowed_rule"}
    url = f"/api/snapshots/{sid}/recommendations/decisions"
    done = client.post(url, headers=admin, json={"status": "accepted", "phase": "never_match"})
    assert done.status_code == 200, done.text
    road = client.get(f"/api/snapshots/{sid}/roadmap").json()
    first = road["phases"][0]
    # What could be accepted was; what was skipped (not executable) is still to decide.
    assert first["accepted"] == done.json()["count"] > 0
    assert first["open"] == sum(done.json()["skipped"].values())
    # Accepted is not done: the phase stays current until its changes are staged.
    assert first["status"] == "current"
    assert road["current"] == "never_match"
    assert client.get(f"/api/snapshots/{sid}/recommendations?phase=nope").status_code == 422
