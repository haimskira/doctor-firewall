"""Connect to the FMC by IP address with a pinned certificate (against the TLS fmc-mock)."""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.collector import runner
from app.core.config import read_secret_file
from app.db.session import get_sessionmaker
from app.fmc.client import ThrottlePolicy
from app.models.audit import AuditRecord
from app.models.fmc import FmcConnection
from app.workers import jobs
from tests.integration.conftest import login, make_user


@pytest.fixture(autouse=True)
def _fast_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner,
        "ThrottlePolicy",
        lambda **_: ThrottlePolicy(requests_per_minute=100_000, burst=1000),
    )


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    make_user("pin-admin", ["admin"])
    return {"X-CSRF-Token": login(client, "pin-admin")}


def _ip() -> str:
    return socket.gethostbyname("fmc-mock")


def _password() -> str:
    return read_secret_file(Path(os.environ["DF_TEST_FMC_PASSWORD_FILE"]))


def _fetch(client: TestClient, h: dict[str, str], host: str) -> dict[str, Any]:
    resp = client.post(
        "/api/fmc/connections/certificate", headers=h, json={"host": host, "port": 443}
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


def _create(client: TestClient, h: dict[str, str], **extra: Any) -> dict[str, Any]:
    resp = client.post(
        "/api/fmc/connections",
        headers=h,
        json={
            "name": "FMC-IP",
            "host": _ip(),
            "port": 443,
            "username": "api_user",
            "password": _password(),
            **extra,
        },
    )
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


def _other_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _actions() -> list[str]:
    with get_sessionmaker()() as s:
        return [r.action for r in s.scalars(select(AuditRecord))]


def test_fetch_returns_the_mock_certificate(client: TestClient, admin: dict[str, str]) -> None:
    info = _fetch(client, admin, _ip())
    der = ssl.PEM_cert_to_DER_cert(ssl.get_server_certificate(("fmc-mock", 443)))
    digest = hashlib.sha256(der).hexdigest().upper()
    assert info["sha256"] == ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
    assert info["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "fmc-mock" in info["subject"]
    assert info["not_before"] < info["not_after"]
    # merely fetching stores and trusts nothing
    with get_sessionmaker()() as s:
        assert s.scalar(select(FmcConnection.id)) is None


def test_fetch_requires_admin(client: TestClient) -> None:
    make_user("pin-viewer", ["viewer"])
    h = {"X-CSRF-Token": login(client, "pin-viewer")}
    resp = client.post(
        "/api/fmc/connections/certificate", headers=h, json={"host": _ip(), "port": 443}
    )
    assert resp.status_code == 403


def test_fetch_unreachable_host_is_a_clear_error(client: TestClient, admin: dict[str, str]) -> None:
    resp = client.post(
        "/api/fmc/connections/certificate", headers=admin, json={"host": "127.0.0.1", "port": 9}
    )
    assert resp.status_code == 502
    assert resp.json()["detail"] == "unreachable"


def test_invalid_pem_is_rejected(client: TestClient, admin: dict[str, str]) -> None:
    resp = client.post(
        "/api/fmc/connections",
        headers=admin,
        json={
            "name": "x",
            "host": _ip(),
            "username": "api_user",
            "password": _password(),
            "pinned_cert": "not a certificate",
        },
    )
    assert resp.status_code == 422


def test_pinned_connection_by_ip_tests_and_collects(
    client: TestClient, admin: dict[str, str]
) -> None:
    ip = _ip()
    info = _fetch(client, admin, ip)
    conn = _create(client, admin, pinned_cert=info["pem"])
    assert conn["host"] == ip
    assert conn["pinned"] is True
    assert conn["pinned_sha256"] == info["sha256"]
    assert "pinned_cert" not in conn

    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=admin).json()
    assert result["ok"] is True, result

    resp = client.post(f"/api/fmc/connections/{conn['id']}/collect", headers=admin)
    assert resp.status_code == 202, resp.text
    assert jobs.collect_snapshot(resp.json()["id"])["ok"] is True

    actions = _actions()
    assert "fmc.certificate.fetch" in actions
    assert "fmc.connection.pin" in actions


def test_pin_is_not_bound_to_the_host_name(client: TestClient, admin: dict[str, str]) -> None:
    info = _fetch(client, admin, "fmc-wrong-name")  # the name is not in the certificate
    conn = _create(client, admin, host="fmc-wrong-name", pinned_cert=info["pem"])
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=admin).json()
    assert result["ok"] is True, result


def test_wrong_pin_fails_with_certificate_changed(
    client: TestClient, admin: dict[str, str]
) -> None:
    conn = _create(client, admin, pinned_cert=_other_pem())
    result = client.post(f"/api/fmc/connections/{conn['id']}/test", headers=admin).json()
    assert result["ok"] is False
    assert result["error"] == "certificate_changed"


def test_changing_host_clears_the_pin_unless_a_new_one_is_sent(
    client: TestClient, admin: dict[str, str]
) -> None:
    info = _fetch(client, admin, _ip())
    conn = _create(client, admin, pinned_cert=info["pem"])
    url = f"/api/fmc/connections/{conn['id']}"

    moved = client.patch(url, headers=admin, json={"host": "fmc-mock", "password": _password()})
    assert moved.status_code == 200, moved.text
    assert moved.json()["pinned"] is False

    again = client.patch(
        url,
        headers=admin,
        json={"host": _ip(), "password": _password(), "pinned_cert": info["pem"]},
    )
    assert again.json()["pinned_sha256"] == info["sha256"]

    renewed = client.patch(url, headers=admin, json={"pinned_cert": _other_pem()})
    assert renewed.status_code == 200
    assert renewed.json()["pinned_sha256"] != info["sha256"]

    cleared = client.patch(url, headers=admin, json={"clear_pin": True})
    assert cleared.json()["pinned"] is False
    assert "fmc.connection.unpin" in _actions()
