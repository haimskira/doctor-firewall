"""Audit chain integrity and database-level privilege separation."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.exc import DBAPIError

from app.audit.chain import AuditEvent
from app.db.session import get_engine, get_sessionmaker
from app.models.audit import AuditRecord
from app.runtime import get_audit
from app.workers.jobs import verify_audit_chain
from tests.integration.conftest import login, make_user


def _append(n: int) -> list[int]:
    ids = []
    with get_sessionmaker()() as s:
        for i in range(n):
            rec = get_audit().record(
                s,
                AuditEvent(
                    actor="test",
                    action="test.event",
                    outcome="success",
                    details={"i": i, "nested": {"ok": True}},
                ),
            )
            ids.append(rec.id)
        s.commit()
    return ids


def test_chain_verifies(clean: None) -> None:
    _append(5)
    with get_sessionmaker()() as s:
        result = get_audit().verify(s)
    assert result.ok
    assert result.checked >= 5


def test_runtime_role_cannot_modify_audit(clean: None) -> None:
    (rid,) = _append(1)
    engine = get_engine()
    for stmt in (
        update(AuditRecord).where(AuditRecord.id == rid).values(actor="evil"),
        text("DELETE FROM audit_log WHERE id = :id").bindparams(id=rid),
        text("TRUNCATE audit_log"),
    ):
        with pytest.raises(DBAPIError, match="permission denied"), engine.begin() as conn:
            conn.execute(stmt)


def test_owner_blocked_by_trigger_and_tampering_detected(clean: None, owner_engine: Engine) -> None:
    (rid,) = _append(1)
    with pytest.raises(DBAPIError, match="append-only"), owner_engine.begin() as conn:
        conn.execute(text("UPDATE audit_log SET actor = 'evil' WHERE id = :id"), {"id": rid})

    # Simulate an attacker with owner rights who disables the trigger and edits a row.
    with owner_engine.begin() as conn:
        original = conn.execute(
            text("SELECT details FROM audit_log WHERE id = :id"), {"id": rid}
        ).scalar_one()
        conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete"))
        conn.execute(
            text("UPDATE audit_log SET details = '{\"i\": 999}'::jsonb WHERE id = :id"),
            {"id": rid},
        )
    try:
        result = verify_audit_chain()
        assert result["ok"] is False
        assert result["broken_at_id"] == rid
        assert result["reason"] == "bad_hash"
    finally:
        with owner_engine.begin() as conn:
            conn.execute(
                text("UPDATE audit_log SET details = CAST(:d AS jsonb) WHERE id = :id"),
                {"d": json.dumps(original), "id": rid},
            )
            conn.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete"))
    assert verify_audit_chain()["ok"] is True


def test_runtime_role_cannot_run_ddl(clean: None) -> None:
    with pytest.raises(DBAPIError, match="permission denied"), get_engine().begin() as conn:
        conn.execute(text("CREATE TABLE evil (id int)"))
    with pytest.raises(DBAPIError, match="permission denied"), get_engine().begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = 'x'"))


def test_audit_api(client: TestClient) -> None:
    make_user("aud", ["approver"])
    csrf = login(client, "aud")
    rows = client.get("/api/audit?limit=5").json()
    assert rows[0]["action"] == "auth.login"
    assert "record_hash" not in rows[0]
    verify = client.post("/api/audit/verify", headers={"X-CSRF-Token": csrf}).json()
    assert verify["ok"] is True
    older = client.get(f"/api/audit?before_id={rows[0]['id']}&limit=1").json()
    assert all(r["id"] < rows[0]["id"] for r in older)
    assert client.get("/api/audit?limit=100000").status_code == 422


def test_concurrent_appends_keep_a_single_chain(clean: None) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: _append(3), range(8)))
    with get_sessionmaker()() as s:
        result = get_audit().verify(s)
        prevs = s.scalars(select(AuditRecord.prev_hash)).all()
    assert result.ok
    assert len(prevs) == len(set(prevs))  # no fork: every hash is extended exactly once
