from __future__ import annotations

import pytest

from app.auth.passwords import (
    PasswordPolicyError,
    check_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.auth.rbac import ROLE_PERMISSIONS, Permission, Role, parse_roles, permissions_for

GOOD = "Correct-Horse-9"


@pytest.mark.parametrize(
    "password",
    ["Short1!", "alllowercaseletters", "a" * 129, "Alice-Password-1"],
)
def test_policy_rejects(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        check_policy(password, "alice")


def test_policy_accepts() -> None:
    check_policy(GOOD, "alice")


def test_hash_and_verify() -> None:
    hashed = hash_password(GOOD)
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, GOOD)
    assert not verify_password(hashed, GOOD + "x")
    assert not needs_rehash(hashed)


def test_verify_unknown_user_and_garbage() -> None:
    assert not verify_password(None, GOOD)
    assert not verify_password("not-a-hash", GOOD)
    assert not verify_password(hash_password(GOOD), "x" * 200)


def test_admin_cannot_deploy_or_edit_changesets() -> None:
    admin = ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.DEPLOY_APPROVE not in admin
    assert Permission.CHANGESET_WRITE not in admin


def test_separation_of_duties() -> None:
    assert Permission.DEPLOY_APPROVE not in ROLE_PERMISSIONS[Role.OPTIMIZER]
    assert Permission.CHANGESET_WRITE not in ROLE_PERMISSIONS[Role.APPROVER]
    assert ROLE_PERMISSIONS[Role.VIEWER] == frozenset({Permission.POLICY_READ})


def test_every_role_can_read_policy() -> None:
    for role in Role:
        assert Permission.POLICY_READ in ROLE_PERMISSIONS[role]


def test_parse_roles_drops_unknown() -> None:
    assert parse_roles(["viewer", "root", "approver"]) == {Role.VIEWER, Role.APPROVER}


def test_permissions_union() -> None:
    perms = permissions_for([Role.OPTIMIZER, Role.APPROVER])
    assert {Permission.CHANGESET_WRITE, Permission.DEPLOY_APPROVE} <= perms
    assert permissions_for([]) == frozenset()
