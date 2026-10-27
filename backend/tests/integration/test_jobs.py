"""Job runs: recorded when queued, progress while running, how they end, lost workers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.collector import runner
from app.db.session import get_sessionmaker
from app.fmc.client import ThrottlePolicy
from app.models.jobs import JobRun
from app.workers import jobs, progress
from tests.integration.conftest import login, make_user
from tests.integration.test_collection import _collect, _connection


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("jobs-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "jobs-admin")}


def _run(**where: Any) -> JobRun:
    with get_sessionmaker()() as s:
        query = select(JobRun).order_by(JobRun.id.desc())
        for key, value in where.items():
            query = query.where(getattr(JobRun, key) == value)
        run = s.scalars(query).first()
        assert run is not None, where
        return run


def test_pull_and_analysis_report_progress_and_end(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    conn_id = _connection(client, admin)
    sid = _collect(client, admin, conn_id)
    queued = _run(snapshot_id=sid, kind="collect")
    assert (queued.status, queued.progress, queued.requested_by) == ("queued", 0, "jobs-admin")
    assert queued.rq_job_id  # the queue knows it
    assert queued.title == "FMC-HA"

    # Record every progress write the worker makes.
    seen: list[tuple[str, int]] = []
    write = progress.Reporter._write

    def spy(self: progress.Reporter, **fields: Any) -> None:
        seen.append((self.step, self.progress))
        write(self, **fields)

    monkeypatch.setattr(progress.Reporter, "_write", spy)
    monkeypatch.setattr(progress, "WRITE_EVERY_SECONDS", 0.0)
    assert jobs.collect_snapshot(sid, run_id=queued.id)["ok"] is True
    done = _run(id=queued.id)
    assert (done.status, done.progress, done.step, done.error) == ("done", 100, "done", None)
    assert done.started_at is not None
    assert done.finished_at is not None
    steps = [s for s, _ in seen]
    for step in ("collect_objects", "collect_topology", "collect_policies", "collect_network"):
        assert step in steps, steps
    values = [p for _, p in seen]
    assert values == sorted(values), "progress never goes back"
    assert any(0 < p < 100 for p in values)

    # The pull queued its analysis as a run of its own, for the same requester.
    analysis = _run(snapshot_id=sid, kind="analyze")
    assert (analysis.status, analysis.requested_by) == ("queued", "jobs-admin")
    seen.clear()
    jobs.analyze_snapshot(sid, run_id=analysis.id)
    assert _run(id=analysis.id).status == "done"
    assert {"analyze_basic", "analyze_rules", "recommend"} <= {s for s, _ in seen}

    response = client.get("/api/jobs")
    assert response.status_code == 200, response.text
    listing = response.json()
    kinds = [(r["kind"], r["status"]) for r in listing["rows"][:2]]
    assert ("analyze", "done") in kinds
    assert ("collect", "done") in kinds
    assert client.get("/api/jobs?state=active").json()["rows"] == []


def test_failures_lost_workers_and_visibility(client: TestClient, admin: dict[str, str]) -> None:
    # A pull that fails (wrong password) ends as failed, with the reason.
    conn_id = _connection(client, admin, password="wrong-password-123")
    sid = _collect(client, admin, conn_id)
    run = _run(snapshot_id=sid, kind="collect")
    assert jobs.collect_snapshot(sid, run_id=run.id)["ok"] is False
    failed = _run(id=run.id)
    assert (failed.status, failed.error) == ("failed", "auth_failed")

    # Runs whose worker is gone are failed when someone looks, not left running forever.
    sessions = get_sessionmaker()
    lost = progress.create_run(sessions, "analyze", "FMC-HA", "jobs-admin", snapshot_id=sid)
    progress.set_rq_job(sessions, lost, "no-such-rq-job")
    stuck = progress.create_run(sessions, "analyze", "FMC-HA", "jobs-admin", snapshot_id=sid)
    with sessions.begin() as s:
        row = s.get(JobRun, stuck)
        assert row is not None
        row.created_at = datetime.now(UTC) - timedelta(minutes=10)
    fresh = progress.create_run(sessions, "analyze", "FMC-HA", "jobs-admin", snapshot_id=sid)
    listing = client.get("/api/jobs?state=all&limit=50").json()
    by_id = {r["id"]: r for r in listing["rows"]}
    assert (by_id[lost]["status"], by_id[lost]["error"]) == ("failed", "worker_lost")
    assert (by_id[stuck]["status"], by_id[stuck]["error"]) == ("failed", "not_queued")
    assert by_id[fresh]["status"] == "queued"  # just created, not yet handed to the queue
    assert listing["active"] >= 1

    # The audit-chain check is shown only to those who may read the audit log.
    jobs.verify_audit_chain()
    assert any(r["kind"] == "audit_verify" for r in client.get("/api/jobs").json()["rows"])
    make_user("jobs-viewer", ["viewer"])
    with TestClient(client.app, base_url="https://testserver") as viewer:
        login(viewer, "jobs-viewer")
        rows = viewer.get("/api/jobs").json()["rows"]
        assert rows
        assert all(r["kind"] != "audit_verify" for r in rows)
        assert viewer.get("/api/jobs?state=sideways").status_code == 422
    with TestClient(client.app, base_url="https://testserver") as anonymous:
        assert anonymous.get("/api/jobs").status_code == 401
