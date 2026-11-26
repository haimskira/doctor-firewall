"""Cancelling a job: queued, during writes, after the deployment started, reverts, permissions."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from rq.job import Job
from rq.serializers import JSONSerializer
from sqlalchemy import select

from app.collector import runner
from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.enforce import executor
from app.enforce.executor import execute_batch, redis_lock
from app.models.audit import AuditRecord
from app.models.enforce import Batch
from app.models.inventory import Snapshot
from app.models.jobs import JobRun
from app.runtime import get_audit, get_redis, get_secretbox
from app.workers import cancel, jobs, progress
from tests.integration.conftest import login, make_user
from tests.integration.test_collection import _collect, _connection
from tests.integration.test_phase5_writes import CONFIG, Flow, _no_wait, mock


@pytest.fixture(autouse=True)
def _fresh_mock() -> Iterator[None]:
    mock("POST", "/mock/reset")
    yield
    mock("POST", "/mock/reset")


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("cancel-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "cancel-admin")}


def _run_batch(batch_id: int, cancel_check: Callable[[], str | None] | None) -> dict[str, Any]:
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
            cancel=cancel_check,
        )
    )


def _status(batch_id: int) -> str:
    with get_sessionmaker()() as s:
        b = s.get(Batch, batch_id)
        assert b is not None
        return b.status


def _job_run(run_id: int) -> JobRun:
    with get_sessionmaker()() as s:
        run = s.get(JobRun, run_id)
        assert run is not None
        return run


def _groups() -> set[str]:
    return {g["name"] for g in mock("GET", CONFIG + "/object/networkgroups")["items"]}


def test_cancel_during_writes_rolls_everything_back(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    split = flow.find("split_rule", "MIXED_TIERS_SQL")
    rename = flow.find("rename_role", "GRP_10.30.0.0")
    _, batch_id = flow.approved_batch([split, rename])
    policy = split["policy_fmc_id"]
    before = flow.rules(policy)["MIXED_TIERS_SQL"]
    calls = {"n": 0}

    def after_first_write() -> str | None:
        calls["n"] += 1
        return None if calls["n"] <= 2 else "alice"  # checks 1-2 pass: the split was written

    result = _run_batch(batch_id, after_first_write)
    assert (result["ok"], result["error"], result["status"]) == (False, "cancelled", "rolled_back")
    assert result["undo_failed"] == []
    after = flow.rules(policy)
    assert "MIXED_TIERS_SQL_SILVER" not in after
    assert after["MIXED_TIERS_SQL"]["destinationNetworks"] == before["destinationNetworks"]
    assert "GRP_10.30.0.0" in _groups()
    with get_sessionmaker()() as s:
        b = s.get(Batch, batch_id)
        assert b is not None
        assert (b.status, (b.error or "").startswith("cancelled: cancelled by alice")) == (
            "rolled_back",
            True,
        )
    flow.close()


def test_cancel_after_the_deployment_started_ends_deployed(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    flow = Flow(client, admin)
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    _, batch_id = flow.approved_batch([unused])
    state = {"deploying": False, "checks_after_deploy": 0}

    def check() -> str | None:
        if state["deploying"]:
            state["checks_after_deploy"] += 1
            return "alice"
        return None

    real_deploy = executor.deploy

    async def deploy_then_cancel(*args: Any, **kwargs: Any) -> Any:
        state["deploying"] = True  # the operator cancels now: too late to stop it
        return await real_deploy(*args, **kwargs)

    monkeypatch.setattr(executor, "deploy", deploy_then_cancel)
    result = _run_batch(batch_id, check)
    assert (result["ok"], result["status"]) == (True, "deployed"), result
    assert state["checks_after_deploy"] == 0  # nothing looks at the flag once it deploys
    assert _status(batch_id) == "deployed"
    flow.close()


def test_job_wrapper_ends_the_run_cancelled_and_clears_the_flag(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    _, batch_id = flow.approved_batch([unused])
    sessions = get_sessionmaker()
    run_id = progress.create_run(sessions, "batch", "t · 1", "p5w-appr", batch_id=batch_id)
    cancel.request(get_redis(), run_id, "p5w-appr")
    result = jobs.execute_batch_job(batch_id, run_id=run_id)
    assert (result["error"], result["status"]) == ("cancelled", "rolled_back")
    run = _job_run(run_id)
    assert (run.status, run.error, run.finished_at is not None) == ("cancelled", "cancelled", True)
    assert cancel.requested(get_redis(), run_id) is None
    assert "GRP_UNUSED" in _groups()  # nothing was written
    flow.close()


def test_revert_stops_between_batches(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = get_sessionmaker()
    run_id = progress.create_run(sessions, "revert", "undo", "p5w-appr", batch_id=102)
    reverted: list[int] = []

    async def revert_then_cancel(batch_id: int, **_: Any) -> dict[str, Any]:
        reverted.append(batch_id)
        cancel.request(get_redis(), run_id, "alice")  # while that batch's undo ran
        return {"ok": True, "status": "reverted"}

    monkeypatch.setattr(jobs, "revert_batch", revert_then_cancel)
    result = jobs.revert_batches_job([102, 101, 100], "p5w-appr", run_id=run_id)
    # The batch being undone finished; the others were never touched.
    assert result == {"ok": False, "cancelled": True, "reverted": [102], "remaining": [101, 100]}
    assert reverted == [102]
    run = _job_run(run_id)
    assert (run.status, run.error) == ("cancelled", "cancelled")
    assert cancel.requested(get_redis(), run_id) is None


def test_resume_rollback_cancelled_while_queued_does_nothing(
    client: TestClient, admin: dict[str, str]
) -> None:
    sessions = get_sessionmaker()
    run_id = progress.create_run(sessions, "rollback", "t · 1", "p5w-appr", batch_id=1)
    cancel.request(get_redis(), run_id, "alice")
    assert jobs.resume_rollback_job(1, run_id=run_id)["cancelled"] is True
    assert _job_run(run_id).status == "cancelled"


def test_cancel_a_queued_batch_run_through_the_api(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    cs_id, batch_id = flow.approved_batch([unused])
    assert (
        flow.appr.post(f"/api/changesets/{cs_id}/batches/1/run", headers=flow.ah).status_code == 202
    )
    with get_sessionmaker()() as s:
        run = s.scalars(
            select(JobRun).where(JobRun.batch_id == batch_id).order_by(JobRun.id.desc())
        ).first()
        assert run is not None
        run_id, rq_id = run.id, run.rq_job_id
    assert rq_id is not None

    # The optimizer (author) may not: only whoever may run batches.
    denied = flow.opt.post(f"/api/jobs/{run_id}/cancel", headers=flow.oh)
    assert denied.status_code == 403
    listing = flow.appr.get("/api/jobs?state=active").json()["rows"]
    assert [r["can_cancel"] for r in listing if r["id"] == run_id] == [True]

    out = flow.appr.post(f"/api/jobs/{run_id}/cancel", headers=flow.ah)
    assert out.status_code == 200, out.text
    assert out.json() == {"run_id": run_id, "result": "cancelled", "deploy_started": False}
    run = _job_run(run_id)
    assert (run.status, run.error) == ("cancelled", "cancelled")
    rq_job = Job.fetch(rq_id, connection=get_redis(), serializer=JSONSerializer)
    assert str(getattr(rq_job.get_status(), "value", "")) == "canceled"
    assert _status(batch_id) == "approved"  # never started: still runnable

    # Not flipped to failed by the "lost worker" reconcile, and finished runs are a 409.
    rows = flow.appr.get("/api/jobs?limit=200").json()["rows"]
    assert [r["status"] for r in rows if r["id"] == run_id] == ["cancelled"]
    again = flow.appr.post(f"/api/jobs/{run_id}/cancel", headers=flow.ah)
    assert (again.status_code, again.json()["detail"]) == (409, "not_cancellable")
    assert flow.appr.post("/api/jobs/999999/cancel", headers=flow.ah).status_code == 404

    with get_sessionmaker()() as s:
        event = s.scalars(
            select(AuditRecord)
            .where(AuditRecord.action == "job.cancel")
            .order_by(AuditRecord.id.desc())
        ).first()
        assert event is not None
        assert (event.actor, event.details["run_id"], event.details["was"]) == (
            "p5w-appr",
            run_id,
            "queued",
        )
    flow.close()


def test_cancel_a_running_write_job_only_sets_the_flag(
    client: TestClient, admin: dict[str, str]
) -> None:
    flow = Flow(client, admin)
    sessions = get_sessionmaker()
    early = progress.create_run(sessions, "batch", "t · 1", "p5w-appr", batch_id=1)
    late = progress.create_run(sessions, "revert", "undo", "p5w-appr", batch_id=1)
    with sessions.begin() as s:
        for run_id, step in ((early, "batch_write"), (late, "deploying")):
            row = s.get(JobRun, run_id)
            assert row is not None
            row.status, row.step = "running", step

    one = flow.appr.post(f"/api/jobs/{early}/cancel", headers=flow.ah)
    assert one.json() == {"run_id": early, "result": "requested", "deploy_started": False}
    assert cancel.requested(get_redis(), early) == "p5w-appr"
    assert _job_run(early).status == "running"  # the worker ends it, at a safe point
    two = flow.appr.post(f"/api/jobs/{late}/cancel", headers=flow.ah)
    assert two.json()["deploy_started"] is True  # accepted, but it cannot stop a deployment
    with sessions.begin() as s:  # leave no running runs behind for other tests
        for run_id in (early, late):
            row = s.get(JobRun, run_id)
            assert row is not None
            row.status = "done"
    flow.close()


def test_cancelled_collection_ends_failed_and_resumable(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn_id = _connection(client, admin)
    sid = _collect(client, admin, conn_id)
    with get_sessionmaker()() as s:
        run = s.scalars(
            select(JobRun).where(JobRun.snapshot_id == sid).order_by(JobRun.id.desc())
        ).first()
        assert run is not None
        run_id = run.id
        snap = s.get(Snapshot, sid)
        assert snap is not None
        snap.status, snap.started_at = "running", datetime.now(UTC)
        run.status = "running"
        s.commit()

    # An approver cannot stop a collection; whoever may start one can.
    make_user("cancel-appr", ["approver"])
    with TestClient(client.app, base_url="https://testserver") as appr:
        h = {"X-CSRF-Token": login(appr, "cancel-appr")}
        assert appr.post(f"/api/jobs/{run_id}/cancel", headers=h).status_code == 403
    out = client.post(f"/api/jobs/{run_id}/cancel", headers=admin)
    assert out.status_code == 200, out.text
    assert out.json()["result"] == "cancelled"
    assert _job_run(run_id).status == "cancelled"
    with get_sessionmaker()() as s:
        snap = s.get(Snapshot, sid)
        assert snap is not None
        assert (snap.status, snap.error) == ("failed", "cancelled")
        runner.prepare_resume(s, snap, timedelta(minutes=30))  # resumable, not stuck running
        assert snap.status == "pending"


def test_a_finished_run_cannot_be_cancelled(client: TestClient, admin: dict[str, str]) -> None:
    sessions = get_sessionmaker()
    run_id = progress.create_run(sessions, "analyze", "FMC", "cancel-admin", snapshot_id=1)
    with sessions.begin() as s:
        row = s.get(JobRun, run_id)
        assert row is not None
        row.status = "done"
    resp = client.post(f"/api/jobs/{run_id}/cancel", headers=admin)
    assert (resp.status_code, resp.json()["detail"]) == (409, "not_cancellable")


def test_a_batch_whose_job_died_is_abandoned_at_once(
    client: TestClient, admin: dict[str, str]
) -> None:
    """A batch left "running" by a job that is no longer queued / running (worker killed,
    job stopped) does not wait for the stale timeout: with nothing written its changeset can
    be cancelled; with writes journaled "finish rollback" is offered (cancel says so)."""
    flow = Flow(client, admin)
    unused = flow.find("remove_unused_object", "GRP_UNUSED")
    cs_id, batch_id = flow.approved_batch([unused])
    with get_sessionmaker().begin() as s:
        b = s.get(Batch, batch_id)
        assert b is not None
        b.status, b.started_at = "running", datetime.now(UTC)  # fresh: not stale by time
        s.add(
            JobRun(
                kind="batch",
                batch_id=batch_id,
                changeset_id=cs_id,
                title="t",
                requested_by="p5w-appr",
                status="failed",
                error="worker_lost",
            )
        )
    url = f"/api/changesets/{cs_id}"
    # Written (journaled) before the job died: roll back first.
    with get_sessionmaker().begin() as s:
        b = s.get(Batch, batch_id)
        assert b is not None
        b.journal = [{"state": "done", "op": "delete", "path": "/x"}]
    batch = flow.opt.get(url).json()["batches"][0]
    assert batch["rollback_resumable"] is True
    refused = flow.opt.post(f"{url}/cancel", headers=flow.oh)
    assert (refused.status_code, refused.json()["detail"]) == (409, "rollback_pending")
    # Nothing written: the changeset cancels at once.
    with get_sessionmaker().begin() as s:
        b = s.get(Batch, batch_id)
        assert b is not None
        b.journal = []
    done = flow.opt.post(f"{url}/cancel", headers=flow.oh)
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "cancelled"
    assert _status(batch_id) == "cancelled"
    flow.close()
