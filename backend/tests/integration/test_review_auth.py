"""Review round: two-administrator rule, lockout DoS, login timing, access.denied spam."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.auth import signin
from app.auth.providers.external import ExternalIdentity, ExternalProvider
from app.auth.throttle import LoginThrottle, remember_login
from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.main import create_app
from app.models.audit import AuditRecord
from app.models.user import User, UserChangeRequest
from tests.integration.conftest import PASSWORD, login, make_user


def _h(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


def _create_body(username: str, roles: list[str]) -> dict[str, Any]:
    return {"username": username, "roles": roles, "temporary_password": "Temp-Pass-1234"}


def _user(username: str) -> User | None:
    with get_sessionmaker()() as s:
        return s.scalar(select(User).where(User.username == username))


# ---- 1. two-administrator rule ----


def test_single_admin_changes_apply_immediately(client: TestClient) -> None:
    make_user("solo", ["admin"])
    csrf = login(client, "solo")
    resp = client.post("/api/users", json=_create_body("appr", ["approver"]), headers=_h(csrf))
    assert resp.status_code == 201


def test_privileged_create_is_queued_and_approved_by_another_admin(client: TestClient) -> None:
    make_user("adm1", ["admin"])
    make_user("adm2", ["admin"])
    csrf1 = login(client, "adm1")
    queued = client.post("/api/users", json=_create_body("appr", ["approver"]), headers=_h(csrf1))
    assert queued.status_code == 202
    assert queued.json()["status"] == "pending"
    request_id = queued.json()["request_id"]
    assert _user("appr") is None
    # No secret in the stored request.
    with get_sessionmaker()() as s:
        row = s.get(UserChangeRequest, request_id)
        assert row is not None
        assert "password" not in str(row.payload).lower()
    # The requester cannot approve his own request.
    own = client.post(f"/api/users/requests/{request_id}/approve", headers=_h(csrf1))
    assert own.status_code == 403
    assert client.get("/api/users/requests").json()[0]["id"] == request_id

    with TestClient(create_app(), base_url="https://testserver") as other:
        csrf2 = login(other, "adm2")
        done = other.post(f"/api/users/requests/{request_id}/approve", headers=_h(csrf2))
        assert done.status_code == 200
        body = done.json()
        assert body["status"] == "approved"
        assert len(body["temporary_password"]) >= 12
        again = other.post(f"/api/users/requests/{request_id}/approve", headers=_h(csrf2))
        assert again.status_code == 409
    created = _user("appr")
    assert created is not None
    assert created.must_change_password is True
    assert created.roles == ["approver"]


def test_viewer_create_needs_no_second_admin(client: TestClient) -> None:
    make_user("adm1", ["admin"])
    make_user("adm2", ["admin"])
    csrf = login(client, "adm1")
    resp = client.post("/api/users", json=_create_body("view", ["viewer"]), headers=_h(csrf))
    assert resp.status_code == 201


def test_role_grant_is_queued(client: TestClient) -> None:
    make_user("adm1", ["admin"])
    make_user("adm2", ["admin"])
    victim = make_user("vic", ["viewer"])
    csrf = login(client, "adm1")
    body = {"roles": ["viewer", "approver"]}
    resp = client.patch(f"/api/users/{victim}", json=body, headers=_h(csrf))
    assert resp.status_code == 202
    user = _user("vic")
    assert user is not None
    assert user.roles == ["viewer"]


def test_privileged_password_reset_is_queued_and_returns_generated_password(
    client: TestClient,
) -> None:
    make_user("adm1", ["admin"])
    make_user("adm2", ["admin"])
    approver_id = make_user("appr", ["approver"])
    csrf1 = login(client, "adm1")
    queued = client.post(
        f"/api/users/{approver_id}/reset-password",
        json={"temporary_password": "Chosen-Pass-77x"},
        headers=_h(csrf1),
    )
    assert queued.status_code == 202
    # The old password still works: nothing changed yet, and the chosen one was not stored.
    with TestClient(create_app(), base_url="https://testserver") as probe:
        assert (
            probe.post(
                "/api/auth/login", json={"username": "appr", "password": "Chosen-Pass-77x"}
            ).status_code
            == 401
        )
    with TestClient(create_app(), base_url="https://testserver") as other:
        csrf2 = login(other, "adm2")
        done = other.post(
            f"/api/users/requests/{queued.json()['request_id']}/approve", headers=_h(csrf2)
        )
        temporary = done.json()["temporary_password"]
        assert temporary != "Chosen-Pass-77x"
    with TestClient(create_app(), base_url="https://testserver") as victim:
        assert (
            victim.post(
                "/api/auth/login", json={"username": "appr", "password": PASSWORD}
            ).status_code
            == 401
        )
        resp = victim.post("/api/auth/login", json={"username": "appr", "password": temporary})
        assert resp.status_code == 200
        assert resp.json()["must_change_password"] is True


def test_reject_and_expiry(client: TestClient) -> None:
    make_user("adm1", ["admin"])
    make_user("adm2", ["admin"])
    csrf1 = login(client, "adm1")
    first = client.post("/api/users", json=_create_body("a1", ["optimizer"]), headers=_h(csrf1))
    second = client.post("/api/users", json=_create_body("a2", ["optimizer"]), headers=_h(csrf1))
    with get_sessionmaker()() as s:
        row = s.get(UserChangeRequest, second.json()["request_id"])
        assert row is not None
        row.requested_at = datetime.now(UTC) - timedelta(hours=25)
        s.commit()
    with TestClient(create_app(), base_url="https://testserver") as other:
        csrf2 = login(other, "adm2")
        rejected = other.post(
            f"/api/users/requests/{first.json()['request_id']}/reject", headers=_h(csrf2)
        )
        assert rejected.status_code == 200
        expired = other.post(
            f"/api/users/requests/{second.json()['request_id']}/approve", headers=_h(csrf2)
        )
        assert (expired.status_code, expired.json()["detail"]) == (409, "request_expired")
    assert _user("a1") is None
    assert _user("a2") is None
    with get_sessionmaker()() as s:
        query = select(AuditRecord.action).where(AuditRecord.action.like("user.request.%"))
        actions = set(s.scalars(query))
    assert actions == {"user.request.create", "user.request.reject"}


def test_target_user_cannot_decide_own_request(client: TestClient) -> None:
    make_user("adm1", ["admin"])
    make_user("adm2", ["admin"])
    adm3 = make_user("adm3", ["admin"])
    csrf = login(client, "adm1")
    queued = client.post(f"/api/users/{adm3}/reset-password", json={}, headers=_h(csrf))
    assert queued.status_code == 202
    with TestClient(create_app(), base_url="https://testserver") as target:
        csrf3 = login(target, "adm3")
        resp = target.post(
            f"/api/users/requests/{queued.json()['request_id']}/approve", headers=_h(csrf3)
        )
        assert resp.status_code == 403


# ---- 2. lockout DoS ----


def test_lockout_does_not_block_a_known_good_ip() -> None:
    redis = fakeredis.FakeRedis()
    throttle = LoginThrottle(redis, max_failures=3, lockout=timedelta(minutes=15))
    throttle.reset("admin", "10.0.0.5")  # a successful sign-in from the admin's own address
    for _ in range(3):
        throttle.register_failure("admin", "203.0.113.9")
    assert throttle.is_locked("admin", "203.0.113.9") is True
    assert throttle.is_locked("admin", "10.0.0.5") is False
    assert redis.ttl(next(iter(redis.scan_iter("df:logintrust:*")))) > 29 * 24 * 3600


def test_known_ip_is_still_throttled_per_ip() -> None:
    redis = fakeredis.FakeRedis()
    throttle = LoginThrottle(redis, max_failures=2, lockout=timedelta(minutes=15))
    remember_login(redis, "admin", "10.0.0.5")
    for i in range(8):
        throttle.register_failure(f"user{i}", "10.0.0.5")
    assert throttle.is_locked("admin", "10.0.0.5") is True


# ---- 3. login timing ----


def test_failed_logins_are_padded_when_an_external_provider_is_enabled(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_user("local1", ["viewer"])
    slept: list[float] = []
    monkeypatch.setattr(signin, "_sleep", slept.append)

    class Deny:
        name = "ldap"

        def verify(self, username: str, password: str) -> ExternalIdentity | None:
            return None

    deny: dict[str, ExternalProvider] = {"ldap": cast(ExternalProvider, Deny())}

    settings = get_settings().model_copy(update={"auth_providers": "local,ldap"})
    with get_sessionmaker()() as db:
        wrong = signin.sign_in(db, settings, "local1", "wrong", providers=deny)
        unknown = signin.sign_in(db, settings, "nobody", "wrong", providers=deny)
        good = signin.sign_in(db, settings, "local1", PASSWORD, providers=deny)
    assert wrong.user is None
    assert unknown.user is None
    assert good.user is not None
    assert len(slept) == 2
    assert all(0 < pause <= signin.FAILED_LOGIN_MIN_SECONDS for pause in slept)


def test_no_padding_with_local_only(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(signin, "_sleep", slept.append)
    with get_sessionmaker()() as db:
        signin.sign_in(db, get_settings(), "nobody", "wrong")
    assert slept == []


# ---- 4. access.denied spam ----


def test_repeated_denials_are_audited_once_per_minute(client: TestClient) -> None:
    make_user("viewer1", ["viewer"])
    login(client, "viewer1")
    for _ in range(5):
        assert client.get("/api/users").status_code == 403
    assert client.get("/api/audit").status_code == 403
    with get_sessionmaker()() as s:
        count = s.scalar(
            select(func.count(AuditRecord.id)).where(AuditRecord.action == "access.denied")
        )
    assert count == 2
