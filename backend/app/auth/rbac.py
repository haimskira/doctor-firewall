"""Roles and permissions.

RBAC is enforced on the server for every endpoint (see :mod:`app.auth.deps`). The
UI only *hides* what a user cannot do; it never grants anything.

Roles follow the spec's separation of duties:

* ``viewer``    — read-only: analysis, map, rulebase.
* ``optimizer`` — builds local changesets from recommendations (never pushes).
* ``approver``  — approves and pushes batches to the FMC.
* ``admin``     — system administration (users, FMC connection, settings). Admin
  does **not** imply optimizer/approver: pushing to a firewall always needs the
  approver role explicitly.

A user may hold several roles. Additional separation rules (e.g. a changeset's
author cannot approve it) are enforced where the action happens.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    OPTIMIZER = "optimizer"
    APPROVER = "approver"
    ADMIN = "admin"


class Permission(StrEnum):
    POLICY_READ = "policy:read"
    CHANGESET_WRITE = "changeset:write"
    DEPLOY_APPROVE = "deploy:approve"
    AUDIT_READ = "audit:read"
    USERS_MANAGE = "users:manage"
    FMC_MANAGE = "fmc:manage"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.POLICY_READ}),
    Role.OPTIMIZER: frozenset({Permission.POLICY_READ, Permission.CHANGESET_WRITE}),
    Role.APPROVER: frozenset(
        {Permission.POLICY_READ, Permission.DEPLOY_APPROVE, Permission.AUDIT_READ}
    ),
    Role.ADMIN: frozenset(
        {
            Permission.POLICY_READ,
            Permission.AUDIT_READ,
            Permission.USERS_MANAGE,
            Permission.FMC_MANAGE,
        }
    ),
}


def parse_roles(values: Iterable[str]) -> frozenset[Role]:
    """Convert stored role names to :class:`Role`; unknown names are dropped (deny-by-default)."""
    known = {r.value for r in Role}
    return frozenset(Role(v) for v in values if v in known)


def permissions_for(roles: Iterable[Role]) -> frozenset[Permission]:
    perms: set[Permission] = set()
    for role in roles:
        perms |= ROLE_PERMISSIONS[role]
    return frozenset(perms)
