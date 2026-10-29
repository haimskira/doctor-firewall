"""Phase 5 (staging): executable plans, changesets, batches under the limit, approvals."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import get_sessionmaker
from app.models.audit import AuditRecord
from app.models.recommendations import Recommendation
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_collection import _collect
from tests.integration.test_phase2 import DOCTRINE_CSV, _snapshot
from tests.integration.test_phase3 import _all


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("p5-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "p5-admin")}


def _analysed(client: TestClient, admin: dict[str, str]) -> int:
    client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV})
    sid = _snapshot(client, admin)
    jobs.analyze_snapshot(sid)
    return sid


def _find(client: TestClient, sid: int, kind: str, name: str) -> dict[str, Any]:
    for rec in _all(client, sid, kind=kind):
        if any(t["name"] == name for t in rec["targets"]):
            detail: dict[str, Any] = client.get(
                f"/api/snapshots/{sid}/recommendations/{rec['id']}"
            ).json()
            return detail
    raise AssertionError(f"{kind} for {name} not found")


def _plan(client: TestClient, sid: int, rec_id: int) -> dict[str, Any]:
    with get_sessionmaker()() as s:
        rec = s.get(Recommendation, rec_id)
        assert rec is not None
        return dict(rec.plan)


def test_recommendations_carry_executable_plans(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)

    split = _find(client, sid, "split_rule", "MIXED_TIERS_SQL")
    plan = _plan(client, sid, split["id"])
    assert plan["executable"] is True
    assert split["executable"] is True
    assert split["blocked"] == []
    assert split["plan"] == plan  # the API detail shows the same operations
    assert [op["op"] for op in plan["ops"]] == ["update_rule", "create_rule"]
    update, create = plan["ops"]
    assert [r["name"] for r in update["set"]["dst_net"]] == ["NET_GOLD_DB"]
    assert update["set"]["dst_net"][0]["type"] == "Network"
    assert update["expect"]["fields"]["dst_net"] == sorted(update["expect"]["fields"]["dst_net"])
    assert len(update["expect"]["fields"]["dst_net"]) == 2
    assert create["copy_from"] == update["rule"]
    assert create["insert_after"] == update["rule"]
    assert create["name"] == "MIXED_TIERS_SQL_SILVER"
    assert [r["name"] for r in create["set"]["dst_net"]] == ["NET_SILVER_APP"]

    shadow = _find(client, sid, "remove_shadowed_rule", "NESTED_LOOP")
    assert [op["op"] for op in _plan(client, sid, shadow["id"])["ops"]] == ["delete_rule"]

    rename = _find(client, sid, "rename_role", "GRP_10.30.0.0")
    op = _plan(client, sid, rename["id"])["ops"][0]
    assert (op["op"], op["type"], op["name"], op["expect"]) == (
        "rename_object",
        "NetworkGroup",
        "GRP_APPS",
        {"name": "GRP_10.30.0.0"},
    )

    dup = _find(client, sid, "merge_duplicate_objects", "dns-primary")
    dup_plan = _plan(client, sid, dup["id"])
    kinds = [op["op"] for op in dup_plan["ops"]]
    assert kinds[-1] == "delete_object"
    assert "update_group" in kinds  # GRP_SVC_DNS held both: now H_DNS1 once
    group_op = next(op for op in dup_plan["ops"] if op["op"] == "update_group")
    assert [m["name"] for m in group_op["members"]] == ["H_DNS1"]
    assert dup["deploy_cost"] == len(dup_plan["ops"])

    # The object a static route uses is the one kept: the merge stays executable.
    gold = _find(client, sid, "merge_duplicate_objects", "net-10.20.5.0")
    gold_plan = _plan(client, sid, gold["id"])
    assert gold_plan["executable"] is True, gold_plan["blocked"]
    assert [op["object_name"] for op in gold_plan["ops"] if op["op"] == "delete_object"] == [
        "net-10.20.5.0"
    ]

    literal = next(
        r for r in _all(client, sid, kind="literal_to_object") if "new object" in r["title"]
    )
    lit_plan = _plan(client, sid, literal["id"])
    assert lit_plan["ops"][0]["op"] == "create_object"
    temp = lit_plan["ops"][0]["temp"]
    assert all(
        any(r.get("temp") == temp for refs in op["set"].values() for r in refs)
        for op in lit_plan["ops"][1:]
    )


def test_changeset_staging_batches_and_approvals(client: TestClient, admin: dict[str, str]) -> None:
    sid = _analysed(client, admin)
    split = _find(client, sid, "split_rule", "MIXED_TIERS_SQL")
    rename = _find(client, sid, "rename_role", "GRP_10.30.0.0")
    unused = _find(client, sid, "remove_unused_object", "GRP_UNUSED")
    merge_groups = _find(client, sid, "merge_groups", "GRP_WEB_SERVERS")
    unused_web = _find(client, sid, "remove_unused_object", "GRP_WEB_SERVERS")
    blocked = _find(client, sid, "merge_duplicate_objects", "dns-primary")
    # Simulate a plan the writer cannot execute (e.g. an object used by a static route).
    with get_sessionmaker().begin() as s:
        stored = s.get(Recommendation, blocked["id"])
        assert stored is not None
        stored.plan = {**stored.plan, "executable": False, "blocked": ["route_reference"]}
    make_user("p5-opt", ["optimizer"])
    make_user("p5-appr", ["approver"])
    make_user("p5-view", ["viewer"])

    with (
        TestClient(client.app, base_url="https://testserver") as opt,
        TestClient(client.app, base_url="https://testserver") as appr,
    ):
        oh = {"X-CSRF-Token": login(opt, "p5-opt")}
        ah = {"X-CSRF-Token": login(appr, "p5-appr")}

        def accept(rec: dict[str, Any]) -> None:
            r = opt.put(
                f"/api/snapshots/{sid}/recommendations/{rec['id']}/decision",
                headers=oh,
                json={"status": "accepted"},
            )
            assert r.status_code == 200

        def create(ids: list[int], ticket: str = "CHG-1001") -> Any:
            return opt.post(
                "/api/changesets",
                headers=oh,
                json={
                    "snapshot_id": sid,
                    "recommendation_ids": ids,
                    "title": "Q4 clean-up",
                    "ticket_id": ticket,
                },
            )

        body = create([split["id"]])
        assert body.status_code == 409
        assert body.json()["detail"] == "not_accepted"
        for rec in (split, rename, unused, merge_groups, unused_web, blocked):
            accept(rec)
        assert create([blocked["id"]]).json() == {
            "detail": "not_executable",
            "recommendations": {str(blocked["id"]): ["route_reference"]},
        }
        clash = create([merge_groups["id"], unused_web["id"]])
        assert clash.status_code == 409
        assert clash.json()["conflicts"][0]["reason"] == "same_object"
        assert create([split["id"]], ticket="bad ticket!").status_code == 422

        # Small deploy limit on every cluster: 2 operations per batch.
        for cluster in client.get(f"/api/snapshots/{sid}/clusters").json():
            client.put(
                f"/api/clusters/{cluster['fmc_id']}/limits",
                headers=admin,
                json={
                    "ace_limit": 1_000_000,
                    "ace_limit_verified": False,
                    "deploy_change_limit": 2,
                    "deploy_limit_verified": True,
                },
            )
        made = create([split["id"], rename["id"], unused["id"]])
        assert made.status_code == 201, made.text
        cs = made.json()
        assert cs["status"] == "open"
        assert cs["created_by"] == "p5-opt"
        assert cs["deploy_limit"] == 2
        assert cs["deploy_limit_verified"] is True
        assert cs["op_count"] == 4
        assert all(b["op_count"] <= b["deploy_limit"] for b in cs["batches"])
        assert [b["status"] for b in cs["batches"]] == ["pending"] * len(cs["batches"])
        # The split (update + create) stays in one batch; the object deletion comes last.
        kinds_by_batch: dict[int, list[str]] = {}
        for item in cs["items"]:
            kinds_by_batch.setdefault(item["batch_seq"], []).append(item["kind"])
        assert ["split_rule"] in kinds_by_batch.values()
        assert cs["items"][-1]["kind"] == "remove_unused_object"
        refused = create([split["id"]]).json()
        assert refused["detail"] == "already_staged"
        assert refused["changesets"] == [{"id": cs["id"], "title": cs["title"]}]
        # The list says which accepted recommendations are already staged, and where; a new
        # changeset only takes the others.
        page = opt.get(f"/api/snapshots/{sid}/recommendations?state=accepted&limit=500").json()
        assert page["accepted_staged"] == len(cs["items"])
        assert page["staged_changesets"] == [{"id": cs["id"], "title": cs["title"]}]
        assert all(r["staged_in"] == cs["id"] for r in page["rows"] if r["id"] == split["id"])
        free = opt.get(
            f"/api/snapshots/{sid}/recommendations?state=accepted&unstaged=true&limit=500"
        ).json()
        assert split["id"] not in {r["id"] for r in free["rows"]}

        # Approvals: never by the author, only by an approver, strictly in order.
        last = cs["batches"][-1]["seq"]
        url = f"/api/changesets/{cs['id']}/batches"
        assert opt.post(f"{url}/1/approve", headers=oh).status_code == 403  # optimizer
        make_user("p5-both", ["optimizer", "approver"])
        with TestClient(client.app, base_url="https://testserver") as both:
            bh = {"X-CSRF-Token": login(both, "p5-both")}
            mine = both.post(
                "/api/changesets",
                headers=bh,
                json={
                    "snapshot_id": sid,
                    "recommendation_ids": [merge_groups["id"]],
                    "title": "Self approval attempt",
                    "ticket_id": "CHG-2002",
                },
            )
            assert mine.status_code == 201, mine.text
            self_approve = both.post(
                f"/api/changesets/{mine.json()['id']}/batches/1/approve", headers=bh
            )
            assert self_approve.status_code == 403
            assert self_approve.json()["detail"] == "author_cannot_approve"
        if last > 1:
            out_of_order = appr.post(f"{url}/{last}/approve", headers=ah)
            assert out_of_order.json()["detail"] == "previous_batch_not_deployed"
        # No approval before the traffic proof of the batch exists (computed by a worker job).
        pending = appr.post(f"{url}/1/approve", headers=ah)
        assert (pending.status_code, pending.json()["detail"]) == (409, "proof_pending")
        jobs.prove_changeset_job(cs["id"])
        proved = client.get(f"/api/changesets/{cs['id']}").json()["batches"]
        assert all(b["proof"]["behavior"] == "preserves" for b in proved)
        assert all(b["proof"]["ok"] and b["proof"]["exhaustive"] for b in proved), proved
        ok = appr.post(f"{url}/1/approve", headers=ah)
        assert ok.status_code == 200
        first = ok.json()["batches"][0]
        assert (first["status"], first["approved_by"]) == ("approved", "p5-appr")
        assert appr.post(f"{url}/1/approve", headers=ah).json()["detail"] == "batch_not_pending"

        with TestClient(client.app, base_url="https://testserver") as viewer:
            vh = {"X-CSRF-Token": login(viewer, "p5-view")}
            assert viewer.get("/api/changesets").status_code == 200
            assert viewer.post(f"/api/changesets/{cs['id']}/cancel", headers=vh).status_code == 403

        cancelled = opt.post(f"/api/changesets/{cs['id']}/cancel", headers=oh).json()
        assert cancelled["status"] == "cancelled"
        assert {b["status"] for b in cancelled["batches"]} == {"cancelled"}
        assert appr.post(f"{url}/1/approve", headers=ah).json()["detail"] == "changeset_closed"
        # Cancelled changesets release their recommendations.
        assert create([split["id"]]).status_code == 201

        # A newer pull (same connection) makes the old snapshot's recommendations stale.
        conn_id = client.get("/api/fmc/connections").json()[0]["id"]
        assert jobs.collect_snapshot(_collect(client, admin, conn_id))["ok"] is True
        assert create([rename["id"]]).json()["detail"] == "snapshot_outdated"

    with get_sessionmaker()() as s:
        actions = list(
            s.scalars(
                select(AuditRecord.action)
                .where(
                    AuditRecord.action.like("changeset.%"),
                    AuditRecord.actor.like("p5-%"),  # this test's users only
                )
                .order_by(AuditRecord.id)
            )
        )
    assert actions[:3] == ["changeset.create", "changeset.create", "changeset.batch_approve"]
    assert "changeset.cancel" in actions
