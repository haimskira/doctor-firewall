from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth.deps import GUARD_ATTR
from app.db.session import get_sessionmaker
from app.main import create_app
from app.models.audit import AuditRecord
from tests.integration.conftest import PASSWORD, login, make_user
from tests.routes import MIN_EXPECTED_ROUTES, iter_api_routes

PUBLIC_ROUTES = {
    ("GET", "/api/health"),
    ("GET", "/api/health/ready"),
    ("POST", "/api/auth/login"),
}


def _guards(dependant: Any) -> list[str]:
    found: list[str] = []
    for dep in dependant.dependencies:
        call: Callable[..., object] | None = dep.call
        if call is not None and hasattr(call, GUARD_ATTR):
            found.append(getattr(call, GUARD_ATTR))
        found.extend(_guards(dep))
    return found


def test_every_route_is_guarded_or_explicitly_public() -> None:
    app = create_app()
    unguarded = []
    routes = list(iter_api_routes(app.routes))
    assert len(routes) >= MIN_EXPECTED_ROUTES, "route walk found too few routes"
    for route in routes:
        for method in route.methods or set():
            if (method, route.path) in PUBLIC_ROUTES:
                assert not _guards(route.dependant), f"public route has a guard: {route.path}"
                continue
            if not _guards(route.dependant):
                unguarded.append(f"{method} {route.path}")
    assert unguarded == []


@pytest.mark.parametrize(
    ("roles", "path", "expected"),
    [
        (["viewer"], "/api/users", 403),
        (["optimizer"], "/api/users", 403),
        (["approver"], "/api/users", 403),
        (["admin"], "/api/users", 200),
        (["viewer"], "/api/audit", 403),
        (["optimizer"], "/api/audit", 403),
        (["approver"], "/api/audit", 200),
        (["admin"], "/api/audit", 200),
        (["viewer"], "/api/fmc/connections", 403),
        (["approver"], "/api/fmc/connections", 403),
        (["admin"], "/api/fmc/connections", 200),
    ],
)
def test_rbac_matrix(client: TestClient, roles: list[str], path: str, expected: int) -> None:
    make_user("u1", roles)
    login(client, "u1")
    assert client.get(path).status_code == expected


def test_denials_are_audited(client: TestClient) -> None:
    make_user("viewer1", ["viewer"])
    login(client, "viewer1")
    assert client.get("/api/users").status_code == 403
    with get_sessionmaker()() as s:
        rec = s.scalar(
            select(AuditRecord)
            .where(AuditRecord.action == "access.denied")
            .order_by(AuditRecord.id.desc())
            .limit(1)
        )
    assert rec is not None
    assert rec.actor == "viewer1"
    assert rec.details == {"required": "users:manage"}


def test_user_admin_lifecycle(client: TestClient) -> None:
    make_user("root1", ["admin"])
    csrf = login(client, "root1")
    h = {"X-CSRF-Token": csrf}

    created = client.post(
        "/api/users",
        json={"username": "Opt1", "roles": ["optimizer"], "temporary_password": "Temp-Pass-1234"},
        headers=h,
    )
    assert created.status_code == 201
    user = created.json()
    assert user["username"] == "opt1"
    assert user["must_change_password"] is True
    assert "password" not in str(user).lower().replace("must_change_password", "")

    dup = client.post(
        "/api/users",
        json={"username": "opt1", "roles": ["viewer"], "temporary_password": "Temp-Pass-1234"},
        headers=h,
    )
    assert dup.status_code == 409

    weak = client.post(
        "/api/users",
        json={"username": "weak", "roles": ["viewer"], "temporary_password": "password"},
        headers=h,
    )
    assert weak.status_code == 400

    bad_role = client.post(
        "/api/users",
        json={"username": "x", "roles": ["superuser"], "temporary_password": "Temp-Pass-1234"},
        headers=h,
    )
    assert bad_role.status_code == 422

    upd = client.patch(
        f"/api/users/{user['id']}", json={"roles": ["optimizer", "approver"]}, headers=h
    )
    assert upd.json()["roles"] == ["approver", "optimizer"]

    reset = client.post(
        f"/api/users/{user['id']}/reset-password",
        json={"temporary_password": "Another-Temp-99"},
        headers=h,
    )
    assert reset.status_code == 200
    assert reset.json()["must_change_password"] is True
    assert client.patch("/api/users/9999", json={"is_active": False}, headers=h).status_code == 404


def test_last_admin_cannot_be_removed(client: TestClient) -> None:
    admin_id = make_user("solo", ["admin"])
    csrf = login(client, "solo")
    h = {"X-CSRF-Token": csrf}
    assert (
        client.patch(f"/api/users/{admin_id}", json={"is_active": False}, headers=h).status_code
        == 409
    )
    assert (
        client.patch(f"/api/users/{admin_id}", json={"roles": ["viewer"]}, headers=h).status_code
        == 409
    )
    make_user("second", ["admin"])
    assert (
        client.patch(
            f"/api/users/{admin_id}", json={"roles": ["viewer", "admin"]}, headers=h
        ).status_code
        == 200
    )


def test_deactivation_kills_sessions(client: TestClient) -> None:
    victim = make_user("victim", ["viewer"])
    make_user("boss", ["admin"])
    with TestClient(client.app, base_url="https://testserver") as other:
        login(other, "victim")
        assert other.get("/api/auth/me").status_code == 200
        csrf = login(client, "boss")
        resp = client.patch(
            f"/api/users/{victim}", json={"is_active": False}, headers={"X-CSRF-Token": csrf}
        )
        assert resp.status_code == 200
        assert other.get("/api/auth/me").status_code == 401
    assert (
        client.post(
            "/api/auth/login", json={"username": "victim", "password": PASSWORD}
        ).status_code
        == 401
    )
