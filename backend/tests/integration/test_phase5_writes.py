"""Phase 5 (writes): approved batches applied to the FMC mock — success, drift, rollback, lock."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import get_settings, read_secret_file
from app.db.session import get_sessionmaker
from app.enforce import executor
from app.enforce.executor import execute_batch, redis_lock, resume_rollback
from app.fmc.client import FmcSession, build_ssl_context
from app.models.audit import AuditRecord
from app.models.enforce import Batch
from app.models.fmc import FmcConnection
from app.models.recommendations import behavior
from app.runtime import get_audit, get_redis, get_secretbox
from app.workers import jobs
from tests.integration.conftest import login, make_user
from tests.integration.test_phase2 import DOCTRINE_CSV, _snapshot
from tests.integration.test_phase3 import _all

CONFIG = "/api/fmc_config/v1/domain/{domain}"


async def _mock(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    """Talk to the FMC mock directly (test setup: reset, faults, out-of-band changes)."""
    password = read_secret_file(Path(os.environ["DF_TEST_FMC_PASSWORD_FILE"]))
    settings = get_settings()
    async with FmcSession(
        host="fmc-mock",
        port=443,
        username="api_user",
        password_provider=lambda: bytearray(password.encode()),
        ssl_context=build_ssl_context(settings.fmc_ca_bundle),
        timeout=30,
    ) as fmc:
        full = path.replace("{domain}", fmc.domain_uuid)
        if method == "GET":
            return await fmc.get_json(full, {"limit": 1000, "expanded": "true"})
        return await fmc.write_json(method, full, body)


def mock(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    return asyncio.run(_mock(method, path, body))


@pytest.fixture(autouse=True)
def _fresh_mock() -> Iterator[None]:
    mock("POST", "/mock/reset")
    yield
    mock("POST", "/mock/reset")


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("p5w-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "p5w-admin")}


async def _no_wait(_seconds: float) -> None:
    return None


def _run(batch_id: int) -> dict[str, Any]:
    return asyncio.run(
        execute_batch(
            batch_id,
            sessions=get_sessionmaker(),
            box=get_secretbox(),
            audit=get_audit(),
            settings=get_settings(),
            lock=redis_lock(get_redis()),
            poll_seconds=0,
            sleep=_no_wait,
        )
    )


def _resume(batch_id: int) -> dict[str, Any]:
    return asyncio.run(
        resume_rollback(
            batch_id,
            sessions=get_sessionmaker(),
            box=get_secretbox(),
            audit=get_audit(),
            settings=get_settings(),
            lock=redis_lock(get_redis()),
            poll_seconds=0,
            sleep=_no_wait,
        )
    )


class Flow:
    """Analyse, accept, stage and approve recommendations through the real API."""

    def __init__(self, client: TestClient, admin: dict[str, str]) -> None:
        client.post("/api/assets/import", headers=admin, json={"csv": DOCTRINE_CSV})
        self.client = client
        self.admin = admin
        self.sid = _snapshot(client, admin)
        jobs.analyze_snapshot(self.sid)
        make_user("p5w-opt", ["optimizer"])
        make_user("p5w-appr", ["approver"])
        self.opt = TestClient(client.app, base_url="https://testserver")
        self.appr = TestClient(client.app, base_url="https://testserver")
        self.oh = {"X-CSRF-Token": login(self.opt, "p5w-opt")}
        self.ah = {"X-CSRF-Token": login(self.appr, "p5w-appr")}

    def find(self, kind: str, name: str) -> dict[str, Any]:
        return next(
            r
            for r in _all(self.client, self.sid, kind=kind)
            if any(t["name"] == name for t in r["targets"])
        )

    def approved_batch(self, recs: list[dict[str, Any]]) -> tuple[int, int]:
        for rec in recs:
            self.opt.put(
                f"/api/snapshots/{self.sid}/recommendations/{rec['id']}/decision",
                headers=self.oh,
                json={"status": "accepted"},
            )
        made = self.opt.post(
            "/api/changesets",
            headers=self.oh,
            json={
                "snapshot_id": self.sid,
                "recommendation_ids": [r["id"] for r in recs],
                "title": "write test",
                "ticket_id": "CHG-5000",
            },
        )
        assert made.status_code == 201, made.text
        cs = made.json()
        assert len(cs["batches"]) == 1
        jobs.prove_changeset_job(cs["id"])  # what the worker does after staging
        url = f"/api/changesets/{cs['id']}/batches/1/approve"
        if any(behavior(r["kind"]) == "changes" for r in recs):
            # Traffic changes by design: approved only when the approver says so.
            refused = self.appr.post(url, headers=self.ah)
            assert refused.json()["detail"] == "behavior_change_unacknowledged", refused.text
            ok = self.appr.post(url, headers=self.ah, json={"acknowledge_change": True})
        else:
            ok = self.appr.post(url, headers=self.ah)
        assert ok.status_code == 200, ok.text
        with get_sessionmaker()() as s:
            batch_id = s.scalar(
                select(Batch.id).where(Batch.changeset_id == cs["id"], Batch.seq == 1)
            )
        assert batch_id is not None
        return cs["id"], batch_id

    def rules(self, policy: str) -> dict[str, dict[str, Any]]:
        listing = mock("GET", CONFIG + f"/policy/accesspolicies/{policy}/accessrules")
        return {r["name"]: r for r in listing["items"]}

    def close(self) -> None:
        self.opt.close()
        self.appr.close()


def test_batch_is_written_verified_and_deployed(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    rename = flow.find("rename_role", "GRP_10.30.0.0")
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    cs_id, batch_id = flow.approved_batch([split, rename, unused])

    # The author can never run it; only an approved batch runs.
    assert (
        flow.opt.post(f"/api/changesets/{cs_id}/batches/1/run", headers=flow.oh).status_code == 403
    )
    result = _run(batch_id)
    assert result["ok"] is True, result
    assert result["status"] == "deployed"
    assert result["operations"] == 4
    assert result["task"]
    cs = client.get(f"/api/changesets/{cs_id}").json()
    assert cs["status"] == "completed"
    assert cs["batches"][0]["status"] == "deployed"
    assert [r["op"] for r in cs["batches"][0]["results"]] == [
        "update_rule",
        "create_rule",
        "rename_object",
        "delete_object",
    ]
    # A completed changeset can never run again.
    with pytest.raises(Exception, match="changeset_closed"):
        _run(batch_id)

    # A fresh read-only pull shows exactly the intended configuration.
    policy = split["policy_fmc_id"]
    rules = flow.rules(policy)
    original = rules["MIXED_TIERS_SQL"]
    added = rules["MIXED_TIERS_SQL_SILVER"]
    assert [o["name"] for o in original["destinationNetworks"]["objects"]] == ["NET_GOLD_DB"]
    assert [o["name"] for o in added["destinationNetworks"]["objects"]] == ["NET_SILVER_APP"]
    assert added["metadata"]["ruleIndex"] == original["metadata"]["ruleIndex"] + 1
    assert added["sourceNetworks"] == original["sourceNetworks"]
    groups = {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert "GRP_APPS" in groups
    assert "GRP_10.30.0.0" not in groups
    assert "GRP_UNUSED" not in groups
    assert "items" not in mock("GET", CONFIG + "/deployment/deployabledevices")  # all deployed

    with get_sessionmaker()() as s:
        actions = list(
            s.scalars(select(AuditRecord.action).where(AuditRecord.action.like("changeset.%")))
        )
    assert "changeset.batch_deployed" in actions
    # What the FMC held after the writes was proved, before deploying, to change no flow.
    proof_after = cs["batches"][0]["proof_after"]
    assert proof_after["ok"] is True
    assert proof_after["behavior"] == "preserves"
    assert proof_after["exhaustive"] is True
    assert proof_after["flows"] > 0
    assert cs["batches"][0]["proof"]["ok"] is True

    # The snapshot no longer matches the FMC: its recommendations say so, the ones carried out
    # are marked applied, and no new changeset may be staged from it (lab: changeset #4).
    applied: set[int] = set()
    for kind in ("split_rule", "rename_role", "remove_unused_object"):
        url = f"/api/snapshots/{flow.sid}/recommendations?limit=500&kind={kind}"
        page = flow.opt.get(url).json()
        assert page["stale"]["changeset_id"] == cs_id
        applied |= {r["id"] for r in page["rows"] if r["applied"]}
    assert {split["id"], rename["id"], unused["id"]} <= applied
    other = flow.find("merge_rules", "WEB_FIN_USERS")
    flow.opt.put(
        f"/api/snapshots/{flow.sid}/recommendations/{other['id']}/decision",
        headers=flow.oh,
        json={"status": "accepted"},
    )
    refused = flow.opt.post(
        "/api/changesets",
        headers=flow.oh,
        json={
            "snapshot_id": flow.sid,
            "recommendation_ids": [other["id"]],
            "title": "from a stale snapshot",
            "ticket_id": "CHG-5001",
        },
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == "snapshot_stale"
    assert refused.json()["changeset"] == cs_id
    flow.close()


def test_compact_group_writes_fewer_members_and_keeps_every_flow(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    rec = flow.find("compact_group", "GRP_COMPACT_ME")
    detail = client.get(f"/api/snapshots/{flow.sid}/recommendations/{rec['id']}").json()
    compact = detail["preview"]["compact"]
    # The host inside the /24 goes; four hosts become one range, two /25s one /24: 8 -> 3.
    assert compact["covered"] == ["H_CMP_IN_BASE"]
    assert (compact["members_before"], compact["members_after"]) == (8, 3)
    assert {m["value"] for m in compact["merged"]} == {"10.70.1.1-10.70.1.4", "10.70.2.0/24"}
    assert detail["ace_delta"] == -5  # COMPACT_RULE: 8 source leaves x 1 -> 3 x 1
    assert behavior(detail["kind"]) == "preserves"

    cs_id, batch_id = flow.approved_batch([rec])
    result = _run(batch_id)
    assert result["ok"] is True, result
    cs = client.get(f"/api/changesets/{cs_id}").json()
    # Proved twice: on the plan before writing, and on what the FMC holds after the writes.
    assert cs["batches"][0]["proof"]["behavior"] == "preserves"
    assert cs["batches"][0]["proof_after"]["behavior"] == "preserves"
    group = next(
        g
        for g in mock("GET", CONFIG + "/object/networkgroups")["items"]
        if g["name"] == "GRP_COMPACT_ME"
    )
    assert len(group["objects"]) == 3
    ranges = {r["value"] for r in mock("GET", CONFIG + "/object/ranges")["items"]}
    assert "10.70.1.1-10.70.1.4" in ranges
    flow.close()


def test_drift_stops_before_any_write(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    cs_id, batch_id = flow.approved_batch([split])
    # Someone edits the rule in the FMC after the snapshot.
    policy = split["policy_fmc_id"]
    rule = flow.rules(policy)["MIXED_TIERS_SQL"]
    body = {k: v for k, v in rule.items() if k not in ("links", "metadata")}
    body["destinationNetworks"] = {"objects": rule["destinationNetworks"]["objects"][:1]}
    mock("PUT", CONFIG + f"/policy/accesspolicies/{policy}/accessrules/{rule['id']}", body)

    result = _run(batch_id)
    assert result["ok"] is False
    assert result["error"] == "drift"
    assert result["status"] == "rolled_back"
    batch = client.get(f"/api/changesets/{cs_id}").json()["batches"][0]
    assert batch["status"] == "rolled_back"
    assert batch["error"].startswith("drift")
    assert "drift: drift" not in batch["error"]  # the code is said once
    assert batch["results"] == []  # nothing was written
    assert "MIXED_TIERS_SQL_SILVER" not in flow.rules(policy)
    flow.close()


def test_failure_mid_batch_rolls_everything_back(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    rename = flow.find("rename_role", "GRP_10.30.0.0")
    _, batch_id = flow.approved_batch([split, rename])
    policy = split["policy_fmc_id"]
    before = flow.rules(policy)["MIXED_TIERS_SQL"]
    # The rename (second item) is refused by the FMC after the split was written.
    mock("POST", "/mock/faults", {"fail_write_on": "GRP_APPS"})

    result = _run(batch_id)
    assert result["ok"] is False
    assert result["error"] == "write_rejected"
    assert result["status"] == "rolled_back", result
    after = flow.rules(policy)
    assert "MIXED_TIERS_SQL_SILVER" not in after
    restored = after["MIXED_TIERS_SQL"]
    assert restored["destinationNetworks"] == before["destinationNetworks"]
    assert restored["id"] == before["id"]
    groups = {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert "GRP_10.30.0.0" in groups
    flow.close()


def test_lost_answer_is_still_undone(client: TestClient, admin: dict[str, str]) -> None:
    """The FMC applied the rename but the answer never came back: the undo restores it anyway."""
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    rename = flow.find("rename_role", "GRP_10.30.0.0")
    _, batch_id = flow.approved_batch([split, rename])
    policy = split["policy_fmc_id"]
    before = flow.rules(policy)["MIXED_TIERS_SQL"]
    mock("POST", "/mock/faults", {"lost_answer_on": "GRP_APPS"})

    result = _run(batch_id)
    assert (result["ok"], result["status"]) == (False, "rolled_back"), result
    groups = {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert "GRP_10.30.0.0" in groups
    assert "GRP_APPS" not in groups
    after = flow.rules(policy)
    assert "MIXED_TIERS_SQL_SILVER" not in after
    assert after["MIXED_TIERS_SQL"]["destinationNetworks"] == before["destinationNetworks"]
    with get_sessionmaker()() as s:
        batch = s.get(Batch, batch_id)
        assert batch is not None
        assert [step["state"] for step in batch.journal] == ["undone"] * 3
    flow.close()


def test_outage_mid_batch_keeps_the_journal_and_resumes(
    client: TestClient, admin: dict[str, str]
) -> None:
    """The lab case: the FMC goes away right after a write; the rollback finishes later."""
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    cs_id, batch_id = flow.approved_batch([split])
    policy = split["policy_fmc_id"]
    before = flow.rules(policy)["MIXED_TIERS_SQL"]
    mock("POST", "/mock/faults", {"outage_on": "MIXED_TIERS_SQL_SILVER"})

    result = _run(batch_id)
    assert (result["ok"], result["status"]) == (False, "failed"), result
    assert len(result["undo_failed"]) == 2
    batch = client.get(f"/api/changesets/{cs_id}").json()["batches"][0]
    assert (batch["undo_pending"], batch["rollback_resumable"]) == (2, True)
    with get_sessionmaker()() as s:
        saved = s.get(Batch, batch_id)
        assert saved is not None
        # The create was sent but never confirmed: its undo finds it by name.
        assert [(x["undo"], x["state"]) for x in saved.journal] == [
            ("restore", "applied"),
            ("delete", "intent"),
        ]
    assert "MIXED_TIERS_SQL_SILVER" in flow.rules(policy)  # the FMC did apply it

    url = f"/api/changesets/{cs_id}/batches/1/rollback"
    assert flow.opt.post(url, headers=flow.oh).status_code == 403  # optimizers cannot
    assert flow.appr.post(url, headers=flow.ah).status_code == 202  # queued for the worker
    mock("POST", "/mock/faults", {})  # the FMC is back
    resumed = _resume(batch_id)
    assert (resumed["ok"], resumed["status"]) == (True, "rolled_back"), resumed
    after = flow.rules(policy)
    assert "MIXED_TIERS_SQL_SILVER" not in after
    assert after["MIXED_TIERS_SQL"]["destinationNetworks"] == before["destinationNetworks"]
    batch = client.get(f"/api/changesets/{cs_id}").json()["batches"][0]
    assert (batch["status"], batch["undo_pending"], batch["rollback_resumable"]) == (
        "rolled_back",
        0,
        False,
    )
    assert not any(r["op"] == "undo_failed" for r in batch["results"])
    assert flow.appr.post(url, headers=flow.ah).status_code == 409  # nothing left to undo
    with get_sessionmaker()() as s:
        actions = list(s.scalars(select(AuditRecord.action)))
    assert "changeset.batch_rollback" in actions
    assert "changeset.batch_rolled_back" in actions
    flow.close()


def test_a_failed_traffic_proof_rolls_back_before_deploying(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """If what the FMC holds after the writes would change a flow, nothing is deployed."""
    with get_sessionmaker()() as s:
        first_record = (s.scalar(select(func.max(AuditRecord.id))) or 0) + 1
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    cs_id, batch_id = flow.approved_batch([split])
    policy = split["policy_fmc_id"]
    before = flow.rules(policy)["MIXED_TIERS_SQL"]

    def changed(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"ok": False, "differences": 1, "flows": 1, "exhaustive": True, "policies": []}

    monkeypatch.setattr(executor, "compare", changed)
    result = _run(batch_id)
    assert (result["ok"], result["error"], result["status"]) == (
        False,
        "proof_failed",
        "rolled_back",
    )
    after = flow.rules(policy)
    assert "MIXED_TIERS_SQL_SILVER" not in after
    assert after["MIXED_TIERS_SQL"]["destinationNetworks"] == before["destinationNetworks"]
    batch = client.get(f"/api/changesets/{cs_id}").json()["batches"][0]
    assert batch["proof_after"]["ok"] is False
    assert batch["error"].startswith("proof_failed")
    with get_sessionmaker()() as s:
        actions = list(s.scalars(select(AuditRecord.action).where(AuditRecord.id >= first_record)))
    assert "changeset.batch_deployed" not in actions
    assert "changeset.batch_rolled_back" in actions
    flow.close()


def test_history_shows_every_change_and_reverts_exactly(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    rename = flow.find("rename_role", "GRP_10.30.0.0")
    cs_id, batch_id = flow.approved_batch([split, rename])
    policy = split["policy_fmc_id"]
    before_rules = flow.rules(policy)
    before_groups = {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert _run(batch_id)["ok"] is True

    entry = next(e for e in client.get("/api/history").json() if e["changeset_id"] == cs_id)
    assert (entry["status"], entry["revert_blocker"]) == ("deployed", None)
    assert entry["proof_after"]["ok"] is True
    changes = client.get(f"/api/changesets/{cs_id}/batches/1/changes").json()
    by_label = {(c["label"], c["action"]): c for c in changes}
    updated = by_label[("MIXED_TIERS_SQL", "changed")]
    dst = next(f for f in updated["fields"] if f["field"] == "destinationNetworks")
    assert "NET_SILVER_APP" in dst["before"]
    assert "NET_SILVER_APP" not in dst["after"]
    assert ("MIXED_TIERS_SQL_SILVER", "created") in by_label
    renamed = by_label[("GRP_10.30.0.0", "changed")]
    assert {"field": "name", "before": "GRP_10.30.0.0", "after": "GRP_APPS"} in renamed["fields"]

    # Revert: exactly the policy before the batch, deployed.
    url = f"/api/changesets/{cs_id}/batches/1/revert"
    assert flow.opt.post(url, headers=flow.oh).status_code == 403  # approvers only
    queued = flow.appr.post(url, headers=flow.ah)
    assert queued.status_code == 202, queued.text
    result = jobs.revert_batches_job([batch_id], "p5w-appr")
    assert result["ok"] is True, result
    after_rules = flow.rules(policy)
    assert list(after_rules) == list(before_rules)  # same rules, same order
    assert (
        after_rules["MIXED_TIERS_SQL"]["destinationNetworks"]
        == before_rules["MIXED_TIERS_SQL"]["destinationNetworks"]
    )
    groups = {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert groups == before_groups
    entry = next(e for e in client.get("/api/history").json() if e["changeset_id"] == cs_id)
    assert entry["status"] == "reverted"
    again = flow.appr.post(url, headers=flow.ah)
    assert (again.status_code, again.json()["detail"]) == (409, "not_deployed")
    with get_sessionmaker()() as s:
        actions = list(s.scalars(select(AuditRecord.action)))
    assert "changeset.batch_revert" in actions
    assert "changeset.batch_revert_ok" in actions
    flow.close()


def test_revert_refuses_when_the_fmc_changed_since(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    cs_id, batch_id = flow.approved_batch([split])
    assert _run(batch_id)["ok"] is True
    # Someone edits the rule the batch created, in the FMC, after the deployment.
    policy = split["policy_fmc_id"]
    created = flow.rules(policy)["MIXED_TIERS_SQL_SILVER"]
    body = {k: v for k, v in created.items() if k not in ("links", "metadata")}
    body["enabled"] = False
    mock("PUT", CONFIG + f"/policy/accesspolicies/{policy}/accessrules/{created['id']}", body)

    result = jobs.revert_batches_job([batch_id], "p5w-appr")
    assert result["ok"] is False
    detail = result["detail"]
    assert (detail["error"], detail["status"]) == ("changed_since", "deployed")
    assert any("MIXED_TIERS_SQL_SILVER" in item for item in detail["items"])
    assert "MIXED_TIERS_SQL_SILVER" in flow.rules(policy)  # nothing was written
    entry = next(e for e in client.get("/api/history").json() if e["changeset_id"] == cs_id)
    assert entry["status"] == "deployed"
    flow.close()


def test_deploy_failure_rolls_back_and_lock_busy_keeps_batch(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    rename = flow.find("rename_role", "GRP_10.30.0.0")
    _, first = flow.approved_batch([unused])

    # Another writer holds the FMC write lock: nothing happens, the batch stays approved.
    redis = get_redis()
    key = "df:fmc-write:fmc-mock:443"
    redis.set(key, "someone-else", ex=60)
    try:
        busy = _run(first)
    finally:
        redis.delete(key)
    assert busy == {"ok": False, "error": "write_lock_busy", "status": "approved"}
    with get_sessionmaker()() as s:
        batch = s.get(Batch, first)
        assert batch is not None
        assert batch.status == "approved"

    mock("POST", "/mock/faults", {"deploy_fail": True})
    result = _run(first)
    assert result["ok"] is False
    assert result["error"] == "deploy_failed"
    # The undo itself succeeded; re-deploying the restored config also hit the injected fault.
    assert result["status"] == "failed"
    assert any("redeploy after rollback" in x for x in result["undo_failed"])
    groups = {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}
    assert "GRP_UNUSED" in groups  # re-created by the rollback

    mock("POST", "/mock/faults", {})
    _, second = flow.approved_batch([rename])
    assert _run(second)["ok"] is True
    flow.close()


def test_run_endpoint_enqueues_an_approved_batch(client: TestClient, admin: dict[str, str]) -> None:
    flow = Flow(client, admin)
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    cs_id, _ = flow.approved_batch([unused])
    url = f"/api/changesets/{cs_id}/batches/1/run"
    make_user("p5w-view", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        assert (
            viewer.post(url, headers={"X-CSRF-Token": login(viewer, "p5w-view")}).status_code == 403
        )
    queued = flow.appr.post(url, headers=flow.ah)
    assert queued.status_code == 202
    assert (
        flow.appr.post(f"/api/changesets/{cs_id}/batches/9/run", headers=flow.ah).status_code == 404
    )
    flow.close()


def test_unreachable_fmc_leaves_the_batch_approved(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing written: the batch can run again, and the operator sees why it did not."""
    monkeypatch.setenv("DF_FMC_CONNECT_RETRIES", "1")  # one short retry, then give up
    get_settings.cache_clear()
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    _cs, batch_id = flow.approved_batch([split])
    with get_sessionmaker()() as s:
        connection = s.scalars(select(FmcConnection)).one()
        connection.host = "fmc-down"  # resolves to nothing: the session cannot open
        s.commit()
    result = _run(batch_id)
    assert (result["ok"], result["status"], result["error"]) == (False, "approved", "unreachable")
    with get_sessionmaker()() as s:
        batch = s.get(Batch, batch_id)
        assert batch is not None
        assert batch.status == "approved"
        assert (batch.error or "").startswith("unreachable")
        actions = list(s.scalars(select(AuditRecord.action)))
    assert "changeset.batch_not_started" in actions
    flow.close()
