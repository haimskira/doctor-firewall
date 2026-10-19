from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth.sessions import SESSION_COOKIE
from app.db.session import get_sessionmaker
from app.models.audit import AuditRecord
from tests.integration.conftest import PASSWORD, login, make_user


def _last_audit(action: str) -> AuditRecord:
    with get_sessionmaker()() as s:
        rec = s.scalar(
            select(AuditRecord)
            .where(AuditRecord.action == action)
            .order_by(AuditRecord.id.desc())
            .limit(1)
        )
        assert rec is not None
        return rec


def test_login_sets_hardened_cookie(client: TestClient) -> None:
    make_user("alice", ["viewer"])
    resp = client.post("/api/auth/login", json={"username": "Alice", "password": PASSWORD})
    assert resp.status_code == 200
    cookie = resp.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attr.lower() in cookie.lower()
    assert "domain=" not in cookie.lower()
    body = resp.json()
    assert body["username"] == "alice"
    assert body["roles"] == ["viewer"]
    assert body["permissions"] == ["policy:read"]
    assert len(body["csrf_token"]) >= 32
    assert _last_audit("auth.login").outcome == "success"


def test_me_requires_session(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_wrong_password_and_unknown_user_look_identical(client: TestClient) -> None:
    make_user("bob", ["viewer"])
    a = client.post("/api/auth/login", json={"username": "bob", "password": "Wrong-Pass-123"})
    b = client.post("/api/auth/login", json={"username": "nobody", "password": "Wrong-Pass-123"})
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"] == b.json()["detail"] == "invalid_credentials"
    assert _last_audit("auth.login").outcome == "failure"


def test_inactive_user_cannot_login(client: TestClient) -> None:
    make_user("carol", ["viewer"], active=False)
    resp = client.post("/api/auth/login", json={"username": "carol", "password": PASSWORD})
    assert resp.status_code == 401


def test_lockout_after_repeated_failures(client: TestClient) -> None:
    make_user("dave", ["viewer"])
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "dave", "password": "Wrong-Pass-123"})
    resp = client.post("/api/auth/login", json={"username": "dave", "password": PASSWORD})
    assert resp.status_code == 429
    assert _last_audit("auth.login").outcome == "denied"


def test_csrf_required_for_state_changes(client: TestClient) -> None:
    make_user("erin", ["viewer"])
    csrf = login(client, "erin")
    assert client.patch("/api/me/preferences", json={"language": "en"}).status_code == 403
    bad = client.patch(
        "/api/me/preferences", json={"language": "en"}, headers={"X-CSRF-Token": "x" * 43}
    )
    assert bad.status_code == 403
    ok = client.patch(
        "/api/me/preferences", json={"language": "en"}, headers={"X-CSRF-Token": csrf}
    )
    assert ok.status_code == 200
    assert ok.json()["language"] == "en"


def test_unknown_fields_rejected(client: TestClient) -> None:
    resp = client.post("/api/auth/login", json={"username": "x", "password": "y", "is_admin": True})
    assert resp.status_code == 422


def test_logout_invalidates_session(client: TestClient) -> None:
    make_user("frank", ["viewer"])
    csrf = login(client, "frank")
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_session_fixation_prevented(client: TestClient) -> None:
    make_user("gina", ["viewer"])
    login(client, "gina")
    first = client.cookies.get(SESSION_COOKIE)
    login(client, "gina")
    second = client.cookies.get(SESSION_COOKIE)
    assert first
    assert second
    assert first != second
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, first)
    assert client.get("/api/auth/me").status_code == 401


def test_forced_password_change_flow(client: TestClient) -> None:
    make_user("hank", ["admin"], must_change=True)
    csrf = login(client, "hank")
    # Everything except self-service is blocked until the password is changed.
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/users").json()["detail"] == "password_change_required"
    weak = client.post(
        "/api/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "short"},
        headers={"X-CSRF-Token": csrf},
    )
    assert weak.status_code == 400
    wrong = client.post(
        "/api/auth/change-password",
        json={"current_password": "Not-The-Pass-1", "new_password": "Brand-New-Pass-77"},
        headers={"X-CSRF-Token": csrf},
    )
    assert wrong.status_code == 400
    old_cookie = client.cookies.get(SESSION_COOKIE)
    ok = client.post(
        "/api/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "Brand-New-Pass-77"},
        headers={"X-CSRF-Token": csrf},
    )
    assert ok.status_code == 200
    assert ok.json()["must_change_password"] is False
    assert client.get("/api/users").status_code == 200
    # The pre-change session is gone.
    assert old_cookie
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, old_cookie)
    assert client.get("/api/auth/me").status_code == 401


def test_readiness(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/health/ready").json() == {"status": "ready"}
