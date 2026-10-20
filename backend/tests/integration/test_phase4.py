"""Phase 4 end-to-end: the connectivity map and the before / after of recommendations."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import DOCTRINE_CSV, _snapshot
from tests.integration.test_phase3 import _all


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("p4-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "p4-admin")}


def _analysed(client: TestClient, admin: dict[str, str]) -> int:
    client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV})
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    return sid


def _map(client: TestClient, sid: int, query: str = "") -> dict[str, Any]:
    resp = client.get(f"/api/snapshots/{sid}/map?limit=5000{query}")
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


def test_map_views_filters_and_risk(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    full = _map(client, sid)
    assert full["view"] == "assets"
    assert full["edges"]
    assert not full["truncated"]
    assert sum(full["risk_counts"].values()) == full["total_edges"] == len(full["edges"])
    node_ids = {n["id"] for n in full["nodes"]}
    assert {e["src"] for e in full["edges"]} | {e["dst"] for e in full["edges"]} == node_ids
    gold = next(n for n in full["nodes"] if n["id"] == "GOLD|SQL-FIN")
    assert gold["networks"] == ["10.20.5.0/24"]
    assert gold["label"] == "SQL-FIN"
    risks = [e["risk"] for e in full["edges"]]
    order = {"red": 0, "yellow": 1, "green": 2}
    assert risks == sorted(risks, key=order.__getitem__)  # worst first
    assert "red" in risks
    for e in full["edges"]:
        assert e["rule_count"] >= 1
        assert len(e["rules"]) <= 20
        assert all({"id", "name", "index", "risk", "policy_id"} <= set(r) for r in e["rules"])

    # Rules that can never match carry no traffic.
    cluster = client.get(f"/api/snapshots/{sid}/clusters").json()[0]
    rows = client.get(
        f"/api/snapshots/{sid}/policies/{cluster['policy_fmc_id']}/rules?limit=500"
    ).json()["rows"]
    on_map = {r["id"] for e in full["edges"] for r in e["rules"]}
    shadowed = {r["id"] for r in rows if r.get("shadowed_by")}
    assert not (on_map & shadowed)
    any_any = next(r for r in rows if r["name"] == "ANY_ANY_TEMP")
    if not any_any["shadowed_by"]:
        edge = next(e for e in full["edges"] if e["src"] == "ANY" and e["dst"] == "ANY")
        assert edge["risk"] == "red"

    system = _map(client, sid, "&view=system")
    tiers = {"CORE", "GOLD", "SILVER", "BRONZE"}
    assert all(
        e["src"].split("|")[0] in tiers and e["dst"].split("|")[0] in tiers for e in system["edges"]
    )
    users = _map(client, sid, "&view=users")
    assert users["edges"]
    assert all(e["src"].startswith("USERS|") or e["src"] == "ANY" for e in users["edges"])

    # Address filters: from BRONZE (10.40/16) -> only DEV or ANY sources.
    bronze = _map(client, sid, "&src=10.40.0.0/16")
    assert {e["src"] for e in bronze["edges"]} <= {"BRONZE|DEV", "ANY"}
    both = _map(client, sid, "&src=10.40.0.0/16&both=true")
    assert len(both["edges"]) >= len(bronze["edges"])
    reds = _map(client, sid, "&risk=red")
    assert reds["edges"]
    assert {e["risk"] for e in reds["edges"]} == {"red"}
    one = _map(client, sid, f"&cluster={cluster['fmc_id']}")
    assert one["total_edges"] <= full["total_edges"]
    capped = _map(client, sid, "&limit=1")
    assert len(capped["edges"]) == 1
    assert capped["truncated"] is (full["total_edges"] > 1)

    assert client.get(f"/api/snapshots/{sid}/map?src=not-an-ip").status_code == 422
    assert client.get(f"/api/snapshots/{sid}/map?view=galaxy").status_code == 422
    assert client.get(f"/api/snapshots/{sid}/map?risk=purple").status_code == 422
    assert client.get("/api/snapshots/999999/map").status_code == 404


def test_recommendation_map_before_after(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    checked = 0
    for kind in ("split_rule", "merge_rules", "remove_dead_rule", "tighten_source"):
        for rec in _all(client, sid, kind=kind)[:5]:
            preview = client.get(f"/api/snapshots/{sid}/recommendations/{rec['id']}").json()[
                "preview"
            ]
            before = {(e["src"], e["dst"]) for e in preview["map"]["before"]}
            after = {(e["src"], e["dst"]) for e in preview["map"]["after"]}
            if kind in ("split_rule", "merge_rules"):
                assert before == after  # behaviour-preserving: same node pairs
            if kind == "remove_dead_rule":
                assert after == set()
                assert all(e["risk"] == "red" for e in preview["map"]["before"])
            if kind == "tighten_source":
                assert all(src != "ANY" for src, _ in after)
            checked += 1
    assert checked > 0


def test_map_rbac(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    make_user("p4-viewer", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        login(viewer, "p4-viewer")
        assert viewer.get(f"/api/snapshots/{sid}/map").status_code == 200
    with TestClient(client.app, base_url="https://testserver") as anon:
        assert anon.get(f"/api/snapshots/{sid}/map").status_code == 401


def test_summary_dashboard(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    resp = client.get(f"/api/snapshots/{sid}/dashboard")
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["snapshot"]["id"] == sid
    totals = d["totals"]
    assert totals["rules"] > 0
    assert totals["clusters"] == len(d["clusters"])
    assert totals["findings"] == sum(d["findings_by_severity"].values())
    assert totals["findings"] == sum(k["count"] for k in d["findings_by_kind"])
    assert totals["recommendations"] == sum(k["count"] for k in d["recommendations_by_kind"])
    assert [b["key"] for b in d["score_buckets"]] == ["0-19", "20-39", "40-59", "60-79", "80-100"]
    assert sum(b["count"] for b in d["score_buckets"]) > 0
    counts = [k["count"] for k in d["findings_by_kind"]]
    assert counts == sorted(counts, reverse=True)
    assert all(c["rule_count"] > 0 and c["ace_total"] for c in d["clusters"])
    full = _map(client, sid)
    assert d["map_risk"] == full["risk_counts"]
    assert len(d["riskiest_connections"]) <= 10
    scores = [w["score"] for w in d["worst_rules"]]
    assert scores == sorted(scores)
    assert client.get("/api/snapshots/999999/dashboard").status_code == 404
