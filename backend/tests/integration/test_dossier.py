"""System dossier API over a collected and analysed snapshot of the FMC mock."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import login, make_user
from tests.integration.test_phase3 import _analysed

SERVICE = re.compile(r"^(any|[A-Z]+(-(any|\d+(-\d+)?))?)$")
KINDS = {"system", "object", "network", "any", "default"}


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("dsr-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "dsr-admin")}


def test_every_system_has_a_consistent_dossier(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    targets = client.get(f"/api/snapshots/{sid}/attack-surface/targets").json()
    assert targets
    seen_kinds: set[str] = set()
    with_peers = 0
    for target in targets:
        resp = client.get(f"/api/snapshots/{sid}/dossier", params={"system": target["id"]})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["system"]["id"] == target["id"]
        assert {c["network"] for c in body["system"]["components"]} == set(target["networks"])
        for side in ("inbound", "outbound"):
            for peer in body[side]:
                seen_kinds.add(peer["kind"])
                assert peer["kind"] in KINDS
                assert peer["rule_count"] >= len(peer["rules"]) >= 1
                assert peer["broad"] + peer["specific"] == peer["rule_count"]
                assert peer["key"] != f"sys:{target['id']}"  # never its own peer
                apps = set(peer["apps"])
                assert all(SERVICE.match(s) for s in peer["services"] if s not in apps), peer
                assert peer["risk"] in {"green", "yellow", "red"}
        if body["inbound"] or body["outbound"]:
            with_peers += 1
        summary = body["summary"]
        assert summary["inbound_peers"] >= len(body["inbound"])
        assert summary["outbound_peers"] >= len(body["outbound"])
    assert with_peers > 0, "the mock rulebase connects some systems"
    assert "system" in seen_kinds


def test_policy_scope_narrows_the_dossier(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    targets = client.get(f"/api/snapshots/{sid}/attack-surface/targets").json()
    policies = [
        p for p in client.get(f"/api/snapshots/{sid}/policies").json() if p["kind"] == "access"
    ]
    target = targets[0]
    everything = client.get(f"/api/snapshots/{sid}/dossier", params={"system": target["id"]}).json()
    for policy in policies:
        scoped = client.get(
            f"/api/snapshots/{sid}/dossier", params={"system": target["id"], "policy": policy["id"]}
        )
        assert scoped.status_code == 200, scoped.text
        for side in ("inbound", "outbound"):
            for peer in scoped.json()[side]:
                assert {r["policy_id"] for r in peer["rules"]} == {policy["id"]}
        if policy["clusters"]:  # an enforced policy is part of the unscoped view
            assert (
                scoped.json()["summary"]["inbound_rules"] <= everything["summary"]["inbound_rules"]
            )


def test_bad_requests(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    base = f"/api/snapshots/{sid}/dossier"
    assert client.get(base).status_code == 422
    assert client.get(base, params={"system": "GOLD|no such system"}).status_code == 404
    assert client.get(base, params={"system": "no-pipe"}).status_code == 404
    assert client.get(base, params={"system": "x" * 300}).status_code == 422
    assert client.get(base, params={"system": "GOLD|x", "policy": "a b"}).status_code == 422
    assert (
        client.get("/api/snapshots/999999/dossier", params={"system": "GOLD|x"}).status_code == 404
    )
