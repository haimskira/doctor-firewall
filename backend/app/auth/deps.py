"""Authentication, CSRF and RBAC enforcement as FastAPI dependencies.

Every route must declare exactly one guard: ``require(<Permission>)``,
``require_authenticated()``, or be listed as public in the route-guard test
(``tests/integration/test_route_guards.py``), which fails the build otherwise.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.chain import AuditEvent, AuditLog
from app.auth import tokens
from app.auth.rbac import Permission, Role, parse_roles, permissions_for
from app.auth.sessions import SESSION_COOKIE, SessionStore
from app.db.session import get_db, get_sessionmaker
from app.models.user import User
from app.runtime import get_audit, get_session_store

log = logging.getLogger(__name__)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "X-CSRF-Token"
GUARD_ATTR = "__df_guard__"


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    roles: frozenset[Role]
    permissions: frozenset[Permission]
    session_id: str
    csrf_token: str
    must_change_password: bool
    language: str
    token_id: int | None = None  # set when the request came with an API token


def client_ip(request: Request) -> str:
    # uvicorn runs with --proxy-headers behind nginx (the only ingress), so
    # request.client reflects the real client address set by nginx.
    return request.client.host if request.client else "unknown"


def _unauthorized() -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "not_authenticated")


def get_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> Principal:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    bearer = request.headers.get("Authorization", "")
    if not session_id and bearer.startswith("Bearer "):
        return _token_principal(request, db, bearer.removeprefix("Bearer ").strip())
    data = store.get(session_id) if session_id else None
    if data is None:
        raise _unauthorized()
    user = db.get(User, data.user_id)
    if user is None or not user.is_active:
        store.delete(session_id)
        raise _unauthorized()
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(sent.encode(), data.csrf_token.encode()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "csrf_failed")
    roles = parse_roles(user.roles)
    return Principal(
        user_id=user.id,
        username=user.username,
        roles=roles,
        permissions=permissions_for(roles),
        session_id=session_id,
        csrf_token=data.csrf_token,
        must_change_password=user.must_change_password,
        language=user.language,
    )


def _token_principal(request: Request, db: Session, token: str) -> Principal:
    """A read-only API token (app.auth.tokens): GET / HEAD, the owner's read permissions only."""
    row = tokens.lookup(db, token)
    if row is None:
        raise _unauthorized()
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    if request.method not in ("GET", "HEAD"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token_read_only")
    roles = parse_roles(user.roles)
    return Principal(
        user_id=user.id,
        username=user.username,
        roles=roles,
        permissions=permissions_for(roles) & tokens.READ_PERMISSIONS,
        session_id="",
        csrf_token="",
        must_change_password=user.must_change_password,
        language=user.language,
        token_id=row.id,
    )


def _audit_denied(audit: AuditLog, principal: Principal, request: Request, needed: str) -> None:
    # Separate short transaction: the request itself is being rejected.
    with get_sessionmaker()() as session:
        audit.record(
            session,
            AuditEvent(
                actor=principal.username,
                actor_id=principal.user_id,
                action="access.denied",
                outcome="denied",
                target=f"{request.method} {request.url.path}",
                source_ip=client_ip(request),
                details={"required": needed},
            ),
        )
        session.commit()


def require(permission: Permission) -> Callable[..., Principal]:
    """Guard: authenticated, password not pending change, and holding ``permission``."""

    def guard(
        request: Request,
        principal: Annotated[Principal, Depends(get_principal)],
        audit: Annotated[AuditLog, Depends(get_audit)],
    ) -> Principal:
        if principal.must_change_password:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password_change_required")
        if permission not in principal.permissions:
            log.warning(
                "permission denied",
                extra={"user": principal.username, "required": permission.value},
            )
            _audit_denied(audit, principal, request, permission.value)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        return principal

    setattr(guard, GUARD_ATTR, permission.value)
    return guard


def require_authenticated(
    *, allow_pending_password_change: bool = False
) -> Callable[..., Principal]:
    """Guard for self-service endpoints that need a session but no specific permission."""

    def guard(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        if principal.must_change_password and not allow_pending_password_change:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password_change_required")
        return principal

    setattr(guard, GUARD_ATTR, "authenticated")
    return guard
