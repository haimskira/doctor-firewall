"""Regressions found in review: API edge cases production users hit and CI did not.

Asset PATCH nulls, CSV import as Excel saves it, FMC connection safety, own-role changes,
change-password guessing, the developer API, the jobs list without Redis, and snapshot
retention / collection ownership.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import redis.exceptions
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.collector import runner
from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.models.enforce import Batch, Changeset
from app.models.inventory import Snapshot
from app.models.jobs import JobRun
from app.models.user import ApiToken
from app.workers import progress
from tests.integration.conftest import PASSWORD, login, make_user

BOM = "\ufeff"


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("review-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "review-admin")}


def _connection(client: TestClient, h: dict[str, str], name: str = "FMC-A") -> int:
    resp = client.post(
        "/api/fmc/connections",
        headers=h,
        json={
            "name": name,
            "host": "fmc-mock",
            "port": 443,
            "username": "api_user",
            "password": "Whatever-Pass-1",
        },
    )
    assert resp.status_code == 201, resp.text
    conn_id: int = resp.json()["id"]
    return conn_id


# ------------------------------------------------------------------ 1: PATCH with null


def test_asset_patch_rejects_null_for_required_fields(
    client: TestClient, admin: dict[str, str]
) -> None:
    group = client.post(
        "/api/asset-groups", headers=admin, json={"name": "FIN", "tier": "GOLD"}
    ).json()
    asset = client.post(
        "/api/assets",
        headers=admin,
        json={"network": "10.20.5.0/24", "system": "SQL", "tier": "GOLD"},
    ).json()
    for field in ("system", "tier", "system_type", "ports", "notes", "confirmed"):
        resp = client.patch(f"/api/assets/{asset['id']}", headers=admin, json={field: None})
        assert resp.status_code == 422, (field, resp.text)
        assert resp.json()["detail"] == "validation_error"
    # Nullable fields keep their meaning.
    moved = client.patch(f"/api/assets/{asset['id']}", headers=admin, json={"group_id": None})
    assert moved.status_code == 200
    assert moved.json()["group_id"] is None
    assert (
        client.patch(
            f"/api/assets/{asset['id']}", headers=admin, json={"user_type": None}
        ).status_code
        == 200
    )

    for field in ("name", "kind", "tier", "owner", "description"):
        resp = client.patch(f"/api/asset-groups/{group['id']}", headers=admin, json={field: None})
        assert resp.status_code == 422, (field, resp.text)
    ok = client.patch(f"/api/asset-groups/{group['id']}", headers=admin, json={"user_type": None})
    assert ok.status_code == 200
    assert ok.json()["name"] == "FIN"


# ------------------------------------------------------------------ 2: CSV as Excel saves it


def test_csv_import_accepts_excel_files(client: TestClient, admin: dict[str, str]) -> None:
    excel = f"{BOM}Network ; System;TIER\r\n10.1.0.0/16;APP;gold\r\n10.2.0.0/16;WEB;silver\r\n"
    resp = client.post("/api/assets/import", headers=admin, json={"csv": excel})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"created": 2, "updated": 0}
    by_net = {a["network"]: a for a in client.get("/api/assets").json()}
    assert by_net["10.1.0.0/16"]["system"] == "APP"
    assert by_net["10.2.0.0/16"]["tier"] == "SILVER"

    comma = f"{BOM}network,system,tier\n10.3.0.0/16,DB,GOLD\n"
    assert client.post("/api/assets/import", headers=admin, json={"csv": comma}).json() == {
        "created": 1,
        "updated": 0,
    }


def test_csv_import_refuses_malformed_and_mis_encoded_files(
    client: TestClient, admin: dict[str, str]
) -> None:
    malformed = 'network,system,tier\n10.1.0.0/16,"unterminated,GOLD\n'
    resp = client.post("/api/assets/import", headers=admin, json={"csv": malformed})
    assert resp.status_code == 422
    assert resp.json()["detail"] == "csv_malformed"

    # Hebrew saved by Excel as windows-1255, then decoded as UTF-8 by the browser.
    garbled = "network,system,tier\n10.1.0.0/16,\ufffd\ufffd\ufffd,GOLD\n"
    resp = client.post("/api/assets/import", headers=admin, json={"csv": garbled})
    assert resp.status_code == 422
    assert resp.json()["detail"] == "csv_encoding"
    assert client.get("/api/assets").json() == []


def test_csv_export_has_bom_and_imports_back_unchanged(
    client: TestClient, admin: dict[str, str]
) -> None:
    values = {
        "10.77.0.0/16": '=HYPERLINK("x")',
        "10.78.0.0/16": "-minus",
        "10.79.0.0/16": "מערכת שכר",
    }
    for network, system in values.items():
        made = client.post(
            "/api/assets",
            headers=admin,
            json={"network": network, "system": system, "tier": "BRONZE", "notes": "+1"},
        )
        assert made.status_code == 201, made.text
    export = client.get("/api/assets/export")
    assert export.content.startswith(b"\xef\xbb\xbf")  # Excel reads it as UTF-8
    assert "'=HYPERLINK" in export.text  # still neutralised for spreadsheets

    back = client.post("/api/assets/import", headers=admin, json={"csv": export.text})
    assert back.status_code == 200, back.text
    assert back.json() == {"created": 0, "updated": 3}
    rows = {a["network"]: a for a in client.get("/api/assets").json()}
    for network, system in values.items():
        assert rows[network]["system"] == system
        assert rows[network]["notes"] == "+1"


# ------------------------------------------------------------------ 3: FMC connections


def test_connection_rename_to_taken_name_is_a_conflict(
    client: TestClient, admin: dict[str, str]
) -> None:
    first = _connection(client, admin, "FMC-A")
    _connection(client, admin, "FMC-B")
    resp = client.patch(f"/api/fmc/connections/{first}", headers=admin, json={"name": "FMC-B"})
    assert resp.status_code == 409
    assert resp.json()["detail"] == "name_taken"
    same = client.patch(f"/api/fmc/connections/{first}", headers=admin, json={"name": "FMC-A"})
    assert same.status_code == 200


def test_stored_password_is_never_sent_to_a_new_host(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn = _connection(client, admin)
    for change in ({"host": "fmc-elsewhere"}, {"port": 8443}, {"username": "other_user"}):
        resp = client.patch(f"/api/fmc/connections/{conn}", headers=admin, json=change)
        assert resp.status_code == 422, change
        assert resp.json()["detail"] == "fmc_password_required"
    stored = client.get("/api/fmc/connections").json()[0]
    assert (stored["host"], stored["port"], stored["username"]) == ("fmc-mock", 443, "api_user")
    # Unchanged values need no password; a new host with its password is fine.
    assert (
        client.patch(
            f"/api/fmc/connections/{conn}", headers=admin, json={"host": "fmc-mock", "port": 443}
        ).status_code
        == 200
    )
    moved = client.patch(
        f"/api/fmc/connections/{conn}",
        headers=admin,
        json={"host": "fmc-elsewhere", "password": "New-Host-Pass-1"},
    )
    assert moved.status_code == 200
    assert moved.json()["host"] == "fmc-elsewhere"


def test_connection_in_use_cannot_be_deleted(client: TestClient, admin: dict[str, str]) -> None:
    conn = _connection(client, admin)
    sessions = get_sessionmaker()
    with sessions.begin() as s:
        cs = Changeset(
            connection_id=conn,
            title="cleanup",
            ticket_id="CHG-1",
            created_by="review-admin",
            deploy_limit=100,
            status="open",
        )
        s.add(cs)
        s.flush()
        cs_id = cs.id

    def refused() -> None:
        resp = client.delete(f"/api/fmc/connections/{conn}", headers=admin)
        assert resp.status_code == 409, resp.text
        assert resp.json()["detail"] == "connection_in_use"

    refused()  # an open changeset
    with sessions.begin() as s:
        s.execute(update(Changeset).where(Changeset.id == cs_id).values(status="failed"))
        s.add(
            Batch(
                changeset_id=cs_id,
                seq=1,
                status="failed",
                op_count=1,
                deploy_limit=100,
                journal=[{"state": "undone"}, {"state": "applied"}],
            )
        )
    refused()  # a failed batch whose rollback is not finished
    with sessions.begin() as s:
        s.execute(
            update(Batch)
            .where(Batch.changeset_id == cs_id)
            .values(journal=[{"state": "undone"}, {"state": "undone"}])
        )
        s.add(
            Snapshot(
                connection_id=conn,
                connection_name="FMC-A",
                status="running",
                requested_by="review-admin",
                stats={},
            )
        )
    refused()  # a collection under way
    with sessions.begin() as s:
        s.execute(update(Snapshot).where(Snapshot.connection_id == conn).values(status="failed"))
    assert client.delete(f"/api/fmc/connections/{conn}", headers=admin).status_code == 204


# ------------------------------------------------------------------ 4: own roles


def test_admin_cannot_change_own_roles(client: TestClient) -> None:
    me = make_user("self-admin", ["admin"])
    other = make_user("other-admin", ["admin"])
    h = {"X-CSRF-Token": login(client, "self-admin")}
    resp = client.patch(f"/api/users/{me}", headers=h, json={"roles": ["admin", "approver"]})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "cannot_change_own_roles"
    # Same roles, or other fields: fine. Someone else's roles: fine.
    assert client.patch(f"/api/users/{me}", headers=h, json={"roles": ["admin"]}).status_code == 200
    assert (
        client.patch(f"/api/users/{me}", headers=h, json={"display_name": "Me"}).status_code == 200
    )
    # Someone else's elevated role: with several admins it waits for a second admin.
    changed = client.patch(f"/api/users/{other}", headers=h, json={"roles": ["admin", "approver"]})
    assert changed.status_code == 202
    assert changed.json()["status"] == "pending"


# ------------------------------------------------------------------ 5: change-password guesses


def test_change_password_guesses_are_throttled_and_end_the_session(client: TestClient) -> None:
    make_user("guesser", ["viewer"])
    h = {"X-CSRF-Token": login(client, "guesser")}
    limit = get_settings().login_max_failures
    for _ in range(limit - 1):
        resp = client.post(
            "/api/auth/change-password",
            headers=h,
            json={"current_password": "Wrong-Guess-123", "new_password": "Brand-New-Pass-77"},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "invalid_current_password"
    last = client.post(
        "/api/auth/change-password",
        headers=h,
        json={"current_password": "Wrong-Guess-123", "new_password": "Brand-New-Pass-77"},
    )
    assert last.status_code == 429
    assert last.json()["detail"] == "too_many_attempts"
    assert client.get("/api/auth/me").status_code == 401  # the session was ended
    # The owner, from the address he signed in from before, is not locked out by the
    # guesses; anyone signing in from elsewhere is.
    relogin = client.post("/api/auth/login", json={"username": "guesser", "password": PASSWORD})
    assert relogin.status_code == 200


# ------------------------------------------------------------------ 6: developer API


def test_openapi_document_is_stable_across_calls(client: TestClient, admin: dict[str, str]) -> None:
    first = client.get("/api/openapi.json?scope=all").json()
    second = client.get("/api/openapi.json?scope=all").json()
    assert first == second
    note = "Signed-in session only"
    for path_ops in second["paths"].values():
        for op in path_ops.values():
            assert (op.get("description") or "").count(note) <= 1
    # The application's own schema is untouched.
    assert note not in str(client.app.openapi())  # type: ignore[attr-defined]


def test_token_limit_ignores_expired_tokens_and_blank_names(client: TestClient) -> None:
    make_user("token-owner", ["viewer"])
    h = {"X-CSRF-Token": login(client, "token-owner")}
    blank = client.post("/api/tokens", headers=h, json={"name": "     "})
    assert blank.status_code == 422
    padded = client.post("/api/tokens", headers=h, json={"name": "  a  "})
    assert padded.status_code == 422
    for n in range(20):
        assert client.post("/api/tokens", headers=h, json={"name": f"token {n}"}).status_code == 201
    assert client.post("/api/tokens", headers=h, json={"name": "one more"}).status_code == 409
    with get_sessionmaker().begin() as s:
        s.execute(update(ApiToken).values(expires_at=datetime.now(UTC) - timedelta(days=1)))
    made = client.post("/api/tokens", headers=h, json={"name": "  after expiry  "})
    assert made.status_code == 201, made.text
    assert made.json()["name"] == "after expiry"


# ------------------------------------------------------------------ 7: jobs without Redis


def test_jobs_list_survives_redis_outage(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = get_sessionmaker()
    run_id = progress.create_run(sessions, "analyze", "FMC-A", "review-admin")
    progress.set_rq_job(sessions, run_id, "some-rq-job")

    def down(*_: Any, **__: Any) -> Any:
        raise redis.exceptions.ConnectionError("redis is down")

    monkeypatch.setattr("rq.job.Job.fetch", down)
    resp = client.get("/api/jobs?state=all&limit=50")
    assert resp.status_code == 200, resp.text
    by_id = {r["id"]: r for r in resp.json()["rows"]}
    assert by_id[run_id]["status"] == "queued"  # unknown, not declared lost
    with sessions() as s:
        row = s.get(JobRun, run_id)
        assert row is not None
        assert row.status == "queued"


# ------------------------------------------------------------------ 11/12: snapshot lifecycle


def test_retention_keeps_complete_snapshots_despite_failed_attempts(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn = _connection(client, admin)
    now = datetime.now(UTC)
    sessions = get_sessionmaker()

    def add(s: Any, status: str, age: timedelta) -> int:
        snap = Snapshot(
            connection_id=conn,
            connection_name="FMC-A",
            status=status,
            requested_by="system:scheduler",
            stats={},
            created_at=now - age,
        )
        s.add(snap)
        s.flush()
        snap_id: int = snap.id
        return snap_id

    with sessions.begin() as s:
        complete = [add(s, "complete", timedelta(days=30 - i)) for i in range(3)]
        recent_failed = [add(s, "failed", timedelta(hours=i + 1)) for i in range(9)]
        old_failed = add(s, "failed", timedelta(days=10))
        old_failed_staged = add(s, "failed", timedelta(days=11))
        s.add(
            Changeset(
                connection_id=conn,
                snapshot_id=old_failed_staged,
                title="history",
                ticket_id="CHG-2",
                created_by="review-admin",
                deploy_limit=100,
                status="completed",
            )
        )
    with sessions.begin() as s:
        deleted = runner.apply_retention(s, conn, keep=2)
    assert deleted == 2
    with sessions() as s:
        remaining = set(s.scalars(select(Snapshot.id).where(Snapshot.connection_id == conn)))
    # The two newest complete snapshots survive nine failed retries; the oldest goes.
    assert complete[1] in remaining
    assert complete[2] in remaining
    assert complete[0] not in remaining
    assert set(recent_failed) <= remaining
    assert old_failed not in remaining
    assert old_failed_staged in remaining  # a changeset was staged from it


def test_a_superseded_collection_does_not_overwrite_its_successor(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn = _connection(client, admin)
    sessions = get_sessionmaker()
    first_start = datetime.now(UTC) - timedelta(hours=2)
    second_start = datetime.now(UTC)
    with sessions.begin() as s:
        snap = Snapshot(
            connection_id=conn,
            connection_name="FMC-A",
            status="running",
            requested_by="review-admin",
            stats={},
            started_at=second_start,  # declared stale and restarted by a second run
            heartbeat_at=second_start,
        )
        s.add(snap)
        s.flush()
        sid = snap.id
    # The first (stale) run finishes late: its outcome is dropped.
    assert not runner._finish(sessions, sid, first_start, status="complete", stats={"x": 1})
    with sessions() as s:
        row = s.get(Snapshot, sid)
        assert row is not None
        assert (row.status, row.stats) == ("running", {})
    # The run that owns it records its outcome.
    assert runner._finish(sessions, sid, second_start, status="complete", stats={"x": 2})
    with sessions() as s:
        row = s.get(Snapshot, sid)
        assert row is not None
        assert (row.status, row.stats) == ("complete", {"x": 2})
