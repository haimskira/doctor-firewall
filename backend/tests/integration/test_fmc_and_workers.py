"""FMC connection management against the TLS mock, secret rotation, and the RQ worker."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from rq.serializers import JSONSerializer
from sqlalchemy import select

from app.cli import main as cli_main
from app.core.config import get_settings, read_secret_file
from app.core.crypto import SecretBox, load_keyring
from app.db.session import get_sessionmaker
from app.models.fmc import FmcConnection
from app.runtime import get_keyring, get_redis
from app.workers.queues import QueueName, get_queue
from app.workers.scheduler import run_due
from app.workers.worker import AllowListWorker
from tests.integration.conftest import login, make_user


def _fmc_password() -> str:
    return read_secret_file(Path(os.environ["DF_TEST_FMC_PASSWORD_FILE"]))


def _admin(client: TestClient) -> dict[str, str]:
    make_user("netadmin", ["admin"])
    return {"X-CSRF-Token": login(client, "netadmin")}


def _create(
    client: TestClient, h: dict[str, str], host: str = "fmc-mock", password: str | None = None
) -> dict[str, object]:
    resp = client.post(
        "/api/fmc/connections",
        json={
            "name": f"FMC {host}",
            "host": host,
            "port": 443,
            "username": "api_user",
            "password": password or _fmc_password(),
        },
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    body: dict[str, object] = resp.json()
    return body


def test_connection_secret_is_never_exposed_and_encrypted(client: TestClient) -> None:
    h = _admin(client)
    conn = _create(client, h)
    assert "password" not in conn
    listing = client.get("/api/fmc/connections").text
    assert _fmc_password() not in listing
    with get_sessionmaker()() as s:
        row = s.scalar(select(FmcConnection))
        assert row is not None
        assert row.password_enc.startswith("v1:")
        assert _fmc_password() not in row.password_enc


def test_probe_over_verified_tls(client: TestClient) -> None:
    h = _admin(client)
    conn = _create(client, h)
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=h).json()
    assert result == {
        "ok": True,
        "server_version": "10.1.0 (build 117)",
        "domain_uuid": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
        "error": None,
    }
    stored = client.get("/api/fmc/connections").json()[0]
    assert stored["last_test_ok"] is True
    assert stored["domain_uuid"] == "e276abec-e0f2-11e3-8169-6d9ed49b625f"


def test_wrong_credentials(client: TestClient) -> None:
    h = _admin(client)
    conn = _create(client, h, password="Definitely-Wrong-1")
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=h).json()
    assert result["ok"] is False
    assert result["error"] == "auth_failed"


def test_hostname_mismatch_is_rejected(client: TestClient) -> None:
    h = _admin(client)
    conn = _create(client, h, host="fmc-wrong-name")
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=h).json()
    assert result == {
        "ok": False,
        "server_version": None,
        "domain_uuid": None,
        "error": "tls_error",
    }


def test_untrusted_ca_is_rejected(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    h = _admin(client)
    conn = _create(client, h)
    monkeypatch.setenv("DF_FMC_CA_BUNDLE", os.environ["DF_TEST_OTHER_CA"])
    get_settings.cache_clear()
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=h).json()
    assert result["error"] == "tls_error"


def test_unreachable_and_update_delete(client: TestClient) -> None:
    h = _admin(client)
    conn = _create(client, h)
    upd = client.patch(
        f"/api/fmc/connections/{conn['id']}",
        json={"host": "fmc-does-not-exist", "port": 8443},
        headers=h,
    )
    assert upd.status_code == 200
    assert upd.json()["last_test_ok"] is None
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=h).json()
    assert result["error"] == "unreachable"
    bad_host = client.patch(
        f"/api/fmc/connections/{conn['id']}", json={"host": "https://evil/x"}, headers=h
    )
    assert bad_host.status_code == 422
    assert client.delete(f"/api/fmc/connections/{conn['id']}", headers=h).status_code == 204
    assert client.get("/api/fmc/connections").json() == []


def test_rotate_secrets_cli(client: TestClient, writable_keyring: Path) -> None:
    h = _admin(client)
    conn = _create(client, h)
    # Operator procedure: add a new key and make it active, keeping the old one so
    # existing ciphertexts and audit signatures stay readable.
    current = json.loads(writable_keyring.read_text(encoding="utf-8"))
    current["keys"]["k-next"] = base64.b64encode(os.urandom(32)).decode()
    current["active"] = "k-next"
    writable_keyring.write_text(json.dumps(current), encoding="utf-8")
    get_keyring.cache_clear()

    assert cli_main(["rotate-secrets"]) == 0
    with get_sessionmaker()() as s:
        row = s.get(FmcConnection, conn["id"])
        assert row is not None
        box = SecretBox(load_keyring(writable_keyring))
        assert box.key_id_of(row.password_enc) == "k-next"
        assert (
            box.decrypt(row.password_enc, FmcConnection.password_context(row.id)).decode()
            == _fmc_password()
        )
    # Still usable end-to-end after rotation.
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=h).json()
    assert result["ok"] is True
    assert cli_main(["verify-audit"]) == 0


def test_scheduler_and_worker_run_allow_listed_job(clean: None) -> None:
    redis = get_redis()
    assert run_due(redis, 10_000_000.0) == ["verify_audit_chain", "auto_collect", "deploy_watch"]
    queue = get_queue(QueueName.MAINTENANCE, redis)
    verify_job, auto_job, watch_job = queue.jobs
    worker = AllowListWorker([queue], connection=redis, serializer=JSONSerializer)
    worker.work(burst=True)
    assert verify_job.get_status(refresh=True) == "finished"
    result = verify_job.return_value(refresh=True)
    assert isinstance(result, dict)
    assert result["ok"] is True
    assert auto_job.get_status(refresh=True) == "finished"
    assert auto_job.return_value(refresh=True) == []  # no connection has auto-sync enabled
    assert watch_job.get_status(refresh=True) == "finished"
    assert isinstance(watch_job.return_value(refresh=True), dict)  # watches checked, by status


def test_worker_rejects_non_allow_listed_job(clean: None) -> None:
    redis = get_redis()
    queue = get_queue(QueueName.MAINTENANCE, redis)
    job = queue.enqueue("os.getcwd")
    worker = AllowListWorker([queue], connection=redis, serializer=JSONSerializer)
    worker.work(burst=True)
    assert job.get_status(refresh=True) == "failed"
    latest = job.latest_result()
    assert latest is not None
    assert "not allow-listed" in (latest.exc_string or "")
