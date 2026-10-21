"""Sign-in through LDAP / TACACS+: provisioning, role sync, local break-glass, audit."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import auth as auth_api
from app.auth import signin
from app.auth.providers.external import ExternalIdentity, ProviderUnavailableError
from app.core.config import Settings
from app.db.session import get_sessionmaker
from app.models.audit import AuditRecord
from app.models.user import User
from tests.integration.conftest import login, make_user


@dataclass
class FakeDirectory:
    name: str
    users: dict[str, tuple[str, frozenset[str] | None]] = field(default_factory=dict)
    down: bool = False

    def verify(self, username: str, password: str) -> ExternalIdentity | None:
        if self.down:
            raise ProviderUnavailableError("directory down")
        known = self.users.get(username)
        if known is None or known[0] != password:
            return None
        return ExternalIdentity(username, username.title(), known[1])


@pytest.fixture
def directory(monkeypatch: pytest.MonkeyPatch) -> FakeDirectory:
    fake = FakeDirectory("ldap")
    settings = Settings(
        auth_providers="local,ldap",
        ldap_url="ldaps://dc1.corp.local",
        ldap_bind_dn="cn=svc,dc=corp,dc=local",
        ldap_user_base="dc=corp,dc=local",
    )
    monkeypatch.setattr(auth_api, "get_settings", lambda: settings)
    monkeypatch.setattr(signin, "external_provider", lambda name, _s, _r: fake)
    return fake


def _audit(reason_actor: str) -> list[dict[str, object]]:
    with get_sessionmaker()() as s:
        return [
            {"outcome": r.outcome, **(r.details or {})}
            for r in s.scalars(
                select(AuditRecord)
                .where(AuditRecord.action == "auth.login", AuditRecord.actor == reason_actor)
                .order_by(AuditRecord.id)
            )
        ]


def test_directory_users_are_provisioned_and_roles_follow_the_directory(
    client: TestClient, directory: FakeDirectory
) -> None:
    directory.users["dana"] = ("Dana-Pass-1", frozenset({"optimizer"}))
    me = client.post("/api/auth/login", json={"username": "dana", "password": "Dana-Pass-1"})
    assert me.status_code == 200, me.text
    body = me.json()
    assert (body["auth_provider"], body["roles"], body["must_change_password"]) == (
        "ldap",
        ["optimizer"],
        False,
    )
    with get_sessionmaker()() as s:
        user = s.scalar(select(User).where(User.username == "dana"))
        assert user is not None
        assert (user.password_hash, user.display_name) == (None, "Dana")

    # The directory changes her groups: the next sign-in carries the new roles.
    directory.users["dana"] = ("Dana-Pass-1", frozenset({"optimizer", "approver"}))
    again = client.post("/api/auth/login", json={"username": "dana", "password": "Dana-Pass-1"})
    assert again.json()["roles"] == ["approver", "optimizer"]
    # Removed from every mapped group: no access at all.
    directory.users["dana"] = ("Dana-Pass-1", frozenset())
    denied = client.post("/api/auth/login", json={"username": "dana", "password": "Dana-Pass-1"})
    assert (denied.status_code, denied.json()["detail"]) == (401, "invalid_credentials")
    # Directory accounts have no local password to change.
    directory.users["dana"] = ("Dana-Pass-1", frozenset({"viewer"}))
    csrf = login(client, "dana", "Dana-Pass-1")
    change = client.post(
        "/api/auth/change-password",
        headers={"X-CSRF-Token": csrf},
        json={"current_password": "Dana-Pass-1", "new_password": "Another-Pass-99"},
    )
    assert change.status_code == 400
    events = _audit("dana")
    assert [e["outcome"] for e in events] == ["success", "success", "failure", "success"]
    assert events[0]["provisioned"] is True
    assert events[1]["roles"] == {"from": ["optimizer"], "to": ["approver", "optimizer"]}
    assert events[2]["reason"] == "no_role"


def test_local_accounts_stay_local_and_failures_are_audited(
    client: TestClient, directory: FakeDirectory
) -> None:
    make_user("root-admin", ["admin"])
    # Same name in the directory with another password: the local account decides.
    directory.users["root-admin"] = ("Directory-Pass-1", frozenset({"viewer"}))
    assert (
        client.post(
            "/api/auth/login", json={"username": "root-admin", "password": "Directory-Pass-1"}
        ).status_code
        == 401
    )
    login(client, "root-admin")  # the local password still works (break-glass)

    directory.down = True
    down = client.post("/api/auth/login", json={"username": "erez", "password": "x-Pass-1234"})
    assert down.status_code == 401
    assert str(_audit("erez")[-1]["reason"]).startswith("provider_unavailable")

    # When the directory does not manage roles, unknown users need an account first.
    directory.down = False
    directory.users["erez"] = ("Erez-Pass-1", None)
    first = client.post("/api/auth/login", json={"username": "erez", "password": "Erez-Pass-1"})
    assert first.status_code == 401
    assert _audit("erez")[-1]["reason"] == "not_provisioned"


def test_admin_creates_directory_accounts(client: TestClient, directory: FakeDirectory) -> None:
    make_user("u-admin", ["admin"])
    h = {"X-CSRF-Token": login(client, "u-admin")}
    made = client.post(
        "/api/users",
        headers=h,
        json={"username": "Erez", "roles": ["approver"], "auth_provider": "tacacs"},
    )
    assert made.status_code == 201, made.text
    assert (made.json()["auth_provider"], made.json()["must_change_password"]) == ("tacacs", False)
    for bad in (
        {
            "username": "x1",
            "roles": ["viewer"],
            "auth_provider": "ldap",
            "temporary_password": "Temp-Pass-1234",
        },
        {"username": "x2", "roles": ["viewer"]},
        {"username": "x3", "roles": ["viewer"], "auth_provider": "radius"},
    ):
        assert client.post("/api/users", headers=h, json=bad).status_code == 422

    # TACACS+ is not enabled in this configuration: the account cannot sign in.
    directory.users["erez"] = ("Erez-Pass-1", None)
    assert (
        client.post(
            "/api/auth/login", json={"username": "erez", "password": "Erez-Pass-1"}
        ).status_code
        == 401
    )
    assert _audit("erez")[-1]["reason"] == "provider_disabled"

    # An LDAP account managed locally (no group mapping) keeps the roles an admin gave it.
    client.post(
        "/api/users",
        headers=h,
        json={"username": "dana", "roles": ["viewer", "optimizer"], "auth_provider": "ldap"},
    )
    directory.users["dana"] = ("Dana-Pass-1", None)
    with TestClient(client.app, base_url="https://testserver") as other:
        me = other.post("/api/auth/login", json={"username": "dana", "password": "Dana-Pass-1"})
        assert me.json()["roles"] == ["optimizer", "viewer"]
