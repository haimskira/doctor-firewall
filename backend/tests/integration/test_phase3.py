"""Phase 3 end-to-end: recommendations, previews, decisions and the naming convention."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import get_sessionmaker
from app.models.audit import AuditRecord
from app.models.inventory import Snapshot
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import DOCTRINE_CSV, _snapshot


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("p3-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "p3-admin")}


def _all(client: TestClient, sid: int, **params: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        query = "&".join(f"{k}={v}" for k, v in {**params, "offset": str(offset)}.items())
        page = client.get(f"/api/snapshots/{sid}/recommendations?limit=500&{query}").json()
        rows += page["rows"]
        offset += len(page["rows"])
        if offset >= page["total"] or not page["rows"]:
            return rows


def _analysed(client: TestClient, admin: dict[str, str]) -> int:
    assert (
        client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV}).status_code
        == 200
    )
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    return sid


def _names(rec: dict[str, Any]) -> set[str]:
    return {t["name"] for t in rec["targets"]}


def test_recommendations_cover_the_doctrine(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    recs = _all(client, sid)
    kinds = {r["kind"] for r in recs}
    assert {
        "remove_shadowed_rule",
        "remove_dead_rule",
        "merge_rules",
        "split_rule",
        "tighten_source",
        "tighten_ports",
        "merge_duplicate_objects",
        "merge_groups",
        "split_group",
        "rename_role",
        "literal_to_object",
        "remove_unused_object",
    } <= kinds
    # A rule that never matches (shadowed) is only ever proposed for removal.
    shadowed = {t["id"] for r in recs if r["kind"] == "remove_shadowed_rule" for t in r["targets"]}
    assert shadowed
    reworked = {
        (r["kind"], t["name"])
        for r in recs
        if r["kind"] != "remove_shadowed_rule"
        for t in r["targets"]
        if t["type"] == "rule" and t["id"] in shadowed
    }
    assert not reworked, reworked
    priorities = [
        r["priority"]
        for r in client.get(f"/api/snapshots/{sid}/recommendations?limit=200").json()["rows"]
    ]
    assert priorities == sorted(priorities, reverse=True)

    cluster = client.get(f"/api/snapshots/{sid}/clusters").json()[0]
    policy = cluster["policy_fmc_id"]
    mine = [r for r in recs if r["policy_fmc_id"] == policy]

    def one(kind: str, name: str) -> dict[str, Any]:
        found = [r for r in mine if r["kind"] == kind and name in _names(r)]
        assert len(found) == 1, (kind, name, [r["title"] for r in mine if r["kind"] == kind][:5])
        detail = client.get(f"/api/snapshots/{sid}/recommendations/{found[0]['id']}").json()
        assert "preview" in detail
        return dict(detail)

    # Shadowed by ANY_ANY_TEMP: removal keeps behaviour; deny behind it is a conflict.
    nested = one("remove_shadowed_rule", "NESTED_LOOP")
    assert nested["deploy_cost"] == 1
    assert nested["warnings"] == []
    assert [a["status"] for a in nested["preview"]["after"]] == ["unchanged", "removed"]
    deny = one("remove_shadowed_rule", "EXPLICIT_DEFAULT_DENY")
    assert deny["warnings"] == ["conflict_intent"]
    assert deny["priority"] > nested["priority"]

    # Split by destination tier: GOLD first, then SILVER; 1 update + 1 create.
    split = one("split_rule", "MIXED_TIERS_SQL")
    assert split["display"] == "split"
    assert split["deploy_cost"] == 2
    before, after = split["preview"]["before"], split["preview"]["after"]
    assert before[0]["fields"]["dst_net"] == ["NET_GOLD_DB", "NET_SILVER_APP"]
    assert [a["status"] for a in after] == ["modified", "new"]
    assert after[0]["fields"]["dst_net"] == ["NET_GOLD_DB"]
    assert after[1]["fields"]["dst_net"] == ["NET_SILVER_APP"]
    assert after[1]["name"] == "MIXED_TIERS_SQL_SILVER"
    assert after[0]["changes"]["dst_net"] == {"added": [], "removed": ["NET_SILVER_APP"]}
    assert split["score_delta"] is not None
    assert split["score_delta"] > 0

    # Adjacent rules that differ only by source merge into the first one.
    merge = one("merge_rules", "WEB_FIN_USERS")
    assert _names(merge) == {"WEB_FIN_USERS", "WEB_IT_USERS"}
    assert merge["deploy_cost"] == 2
    merged = merge["preview"]["after"][0]
    assert merged["fields"]["src_net"] == ["GRP_SRC_FIN", "GRP_SRC_IT"]
    assert [a["status"] for a in merge["preview"]["after"]] == ["modified", "removed"]

    # Any source behind the users zone -> the networks routed through it.
    tighten = one("tighten_source", "USERS_ZONE_TO_GOLD")
    sources = tighten["preview"]["after"][0]["fields"]["src_net"]
    assert "NET_USERS_GENERAL" in sources
    assert "10.100.1.0/24" in sources
    assert set(tighten["warnings"]) == {"derived_from_routing", "literal_needs_object"}

    # Any port toward SQL-FIN -> its declared TCP 1433, via the existing object.
    ports = one("tighten_ports", "TEMP_DEV_TO_DB")
    assert ports["preview"]["after"][0]["fields"]["dst_port"] == ["SVC_TCP1433"]
    assert ports["score_delta"] is not None
    assert ports["score_delta"] > 0

    # Object-level recommendations (estate-wide).
    def obj(kind: str, name: str) -> dict[str, Any]:
        found = [r for r in recs if r["kind"] == kind and name in _names(r)]
        assert found, (kind, name)
        return dict(client.get(f"/api/snapshots/{sid}/recommendations/{found[0]['id']}").json())

    dup = obj("merge_duplicate_objects", "dns-primary")
    assert _names(dup) == {"H_DNS1", "dns-primary"}
    after_objects = dup["preview"]["objects"]["after"]
    assert [o["status"] for o in after_objects] == ["kept", "removed"]
    groups = obj("merge_groups", "GRP_WEB_SERVERS")
    assert groups["preview"]["objects"]["after"][0]["name"] == "GRP_10.30.0.0"  # referenced one
    split_group = obj("split_group", "GRP_DC_ALL")
    new = [o for o in split_group["preview"]["objects"]["after"] if o["status"] == "new"]
    assert [o["tier"] for o in new] == ["GOLD", "SILVER", "UNCLASSIFIED"]
    assert "unclassified_part" in split_group["warnings"]
    role = obj("rename_role", "GRP_10.30.0.0")
    assert role["preview"]["rename"] == {
        "from": "GRP_10.30.0.0",
        "to": "GRP_APPS",
        "kind": "network_group",
    }
    assert "external_references" in role["warnings"]
    unused = obj("remove_unused_object", "GRP_UNUSED")
    assert unused["deploy_cost"] == 1
    literal = next(r for r in recs if r["kind"] == "literal_to_object")
    assert literal["deploy_cost"] >= 1

    # The policy editor shows the tags on the rules.
    rows = {
        r["name"]: r
        for r in client.get(
            f"/api/snapshots/{sid}/policies/{policy}/rules?limit=500&q=MIXED"
        ).json()["rows"]
    }
    assert "split_rule" in {t["kind"] for t in rows["MIXED_TIERS_SQL"]["recommendations"]}

    # Filters and stats.
    only = client.get(
        f"/api/snapshots/{sid}/recommendations?kind=split_rule&policy={policy}"
    ).json()
    assert {r["kind"] for r in only["rows"]} == {"split_rule"}
    assert only["summary"]["split_rule"]["count"] >= 1
    by_rule = client.get(
        f"/api/snapshots/{sid}/recommendations?rule={split['targets'][0]['id']}"
    ).json()
    assert {r["kind"] for r in by_rule["rows"]} >= {"split_rule"}
    with get_sessionmaker()() as s:
        snap = s.get(Snapshot, sid)
        assert snap is not None
        assert snap.stats["recommendations"]["split_rule"] >= 1
    assert client.get(f"/api/snapshots/{sid}/recommendations?kind=bogus").status_code == 422
    assert client.get(f"/api/snapshots/{sid}/recommendations/999999999").status_code == 404


def test_decisions_survive_reanalysis(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    rec = _all(client, sid, kind="split_rule")[0]
    make_user("p3-opt", ["optimizer"])
    make_user("p3-viewer", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "p3-viewer")}
        assert viewer.get(f"/api/snapshots/{sid}/recommendations").status_code == 200
        denied = viewer.put(
            f"/api/snapshots/{sid}/recommendations/{rec['id']}/decision",
            headers=h,
            json={"status": "accepted"},
        )
        assert denied.status_code == 403
    # Admin has no changeset permission (separation of duties).
    assert (
        client.put(
            f"/api/snapshots/{sid}/recommendations/{rec['id']}/decision",
            headers=admin,
            json={"status": "accepted"},
        ).status_code
        == 403
    )
    with TestClient(client.app, base_url="https://testserver") as opt:
        h = {"X-CSRF-Token": login(opt, "p3-opt")}
        url = f"/api/snapshots/{sid}/recommendations/{rec['id']}/decision"
        assert opt.put(url, headers=h, json={"status": "maybe"}).status_code == 422
        assert opt.put(url, headers=h, json={"status": "accepted", "x": 1}).status_code == 422
        accepted = opt.put(url, headers=h, json={"status": "accepted", "note": "CHG-1234"})
        assert accepted.status_code == 200
        assert accepted.json()["decision"]["status"] == "accepted"
        assert accepted.json()["decision"]["decided_by"] == "p3-opt"
        page = opt.get(f"/api/snapshots/{sid}/recommendations?state=accepted").json()
        assert [r["id"] for r in page["rows"]] == [rec["id"]]
        assert page["accepted"]["count"] == 1
        assert page["accepted"]["deploy_cost"] == rec["deploy_cost"]
        # Re-analysis regenerates recommendations; the decision follows the fingerprint.
        jobs.analyze_snapshot(sid)
        again = _all(opt, sid, state="accepted")
        assert [r["fingerprint"] for r in again] == [rec["fingerprint"]]
        assert again[0]["decision"]["note"] == "CHG-1234"
        new_id = again[0]["id"]
        dismissed = opt.put(
            f"/api/snapshots/{sid}/recommendations/{new_id}/decision",
            headers=h,
            json={"status": "dismissed"},
        )
        assert dismissed.json()["decision"]["status"] == "dismissed"
        reopened = opt.put(
            f"/api/snapshots/{sid}/recommendations/{new_id}/decision",
            headers=h,
            json={"status": "open"},
        )
        assert reopened.json()["decision"] is None
        assert opt.get(f"/api/snapshots/{sid}/recommendations?state=accepted").json()["total"] == 0
    with get_sessionmaker()() as s:
        actions = list(
            s.scalars(
                select(AuditRecord.action)
                .where(AuditRecord.action.like("recommendation.%"))
                .order_by(AuditRecord.id)
            )
        )
    assert actions == [
        "recommendation.accepted",
        "recommendation.dismissed",
        "recommendation.open",
    ]


def test_naming_convention(client: TestClient, admin: dict[str, str]) -> None:
    catalog = client.get("/api/naming-conventions").json()
    assert "ROLE" in catalog["kinds"]["network_group"]
    assert catalog["conventions"] == []
    bad = client.put(
        "/api/naming-conventions/network_group", headers=admin, json={"template": "GRP_<PORT>"}
    )
    assert bad.status_code == 422
    assert bad.json()["detail"] == "template_unknown_token"
    assert (
        client.put(
            "/api/naming-conventions/planet", headers=admin, json={"template": "X_<ROLE>"}
        ).status_code
        == 422
    )
    ok = client.put(
        "/api/naming-conventions/network_group",
        headers=admin,
        json={"template": "GRP_<ROLE>", "letter_case": "upper"},
    )
    assert ok.status_code == 200
    assert ok.json()["updated_by"] == "p3-admin"
    rule = client.put(
        "/api/naming-conventions/rule", headers=admin, json={"template": "<SRC>_TO_<DST>_<SVC>"}
    )
    assert rule.status_code == 200
    make_user("p3-opt2", ["optimizer"])
    with TestClient(client.app, base_url="https://testserver") as opt:
        h = {"X-CSRF-Token": login(opt, "p3-opt2")}
        denied = opt.put("/api/naming-conventions/host", headers=h, json={"template": "H_<VALUE>"})
        assert denied.status_code == 403
        assert opt.get("/api/naming-conventions").status_code == 200

    sid = _analysed(client, admin)
    renames = _all(client, sid, kind="rename_convention")
    details = [
        client.get(f"/api/snapshots/{sid}/recommendations/{r['id']}").json() for r in renames
    ]
    by_from = {d["targets"][0]["name"]: d for d in details}
    dns = by_from["GRP_SVC_DNS"]
    assert dns["preview"]["rename"]["to"] == "GRP_DNS"
    assert dns["preview"]["affected_rules"]["total"] > 0
    assert "external_references" in dns["warnings"]
    # The rule name comes from the asset table (source / destination) and the rule's ports.
    # The random part of the mock estate has rules with the same source, destination and
    # service in the same policy, so names collide and get a suffix (flagged).
    webs = [d for d in details if d["targets"][0]["name"] == "WEB_FIN_USERS"]
    assert webs
    for web in webs:
        after = web["preview"]["after"][0]
        assert after["name"].startswith("FIN-USERS_TO_APPS_HTTPS-HTTP")
        assert after["changes"]["name"]["removed"] == ["WEB_FIN_USERS"]
        if after["name"] != "FIN-USERS_TO_APPS_HTTPS-HTTP":
            assert "name_disambiguated" in web["warnings"]
    policy_names: dict[str, list[str]] = {}
    for d in details:
        if d["policy_fmc_id"] is not None:
            policy_names.setdefault(d["policy_fmc_id"], []).append(d["preview"]["after"][0]["name"])
    for names in policy_names.values():
        assert len(names) == len({n.lower() for n in names})  # no two proposals collide
    assert "FIN-APP_TO_GOLD-DB_SQL" not in by_from  # already compliant
    with get_sessionmaker()() as s:
        snap = s.get(Snapshot, sid)
        assert snap is not None
        assert snap.stats["naming"]["rule"]["compliant"] >= 2
        assert snap.stats["naming"]["network_group"]["noncompliant"] > 0

    assert client.delete("/api/naming-conventions/rule", headers=admin).status_code == 204
    assert client.delete("/api/naming-conventions/rule", headers=admin).status_code == 404
    assert [c["kind"] for c in client.get("/api/naming-conventions").json()["conventions"]] == [
        "network_group"
    ]


def test_reanalysis_request(client: TestClient, admin: dict[str, str]) -> None:
    sid = _snapshot(client, admin)
    resp = client.post(f"/api/snapshots/{sid}/analyze", headers=admin)
    assert resp.status_code == 202
    assert resp.json() == {"snapshot_id": sid}
    assert client.post("/api/snapshots/999999/analyze", headers=admin).status_code == 404
    make_user("p3-view2", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        h = {"X-CSRF-Token": login(viewer, "p3-view2")}
        assert viewer.post(f"/api/snapshots/{sid}/analyze", headers=h).status_code == 403
