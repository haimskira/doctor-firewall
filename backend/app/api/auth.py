from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.schemas import ChangePasswordRequest, LoginRequest, MeResponse, PreferencesRequest
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require_authenticated
from app.auth.passwords import PasswordPolicyError, check_policy, hash_password, verify_password
from app.auth.rbac import parse_roles, permissions_for
from app.auth.sessions import SESSION_COOKIE, SessionStore
from app.auth.signin import sign_in
from app.auth.throttle import LoginThrottle
from app.core.config import get_settings
from app.db.session import get_db
from app.models.user import User
from app.runtime import get_audit, get_login_throttle, get_session_store

router = APIRouter(prefix="/api", tags=["auth"])

DbDep = Annotated[Session, Depends(get_db)]
StoreDep = Annotated[SessionStore, Depends(get_session_store)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
# Self-service endpoints stay reachable while a password change is pending.
SelfDep = Annotated[Principal, Depends(require_authenticated(allow_pending_password_change=True))]


def _set_session_cookie(response: Response, session_id: str) -> None:
    # __Host- prefix forces Secure, Path=/ and no Domain attribute in browsers.
    response.set_cookie(
        SESSION_COOKIE, session_id, httponly=True, secure=True, samesite="strict", path="/"
    )


def _me(user: User, csrf_token: str) -> MeResponse:
    roles = parse_roles(user.roles)
    return MeResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        auth_provider=user.auth_provider,
        roles=sorted(roles),
        permissions=sorted(p.value for p in permissions_for(roles)),
        language="en" if user.language == "en" else "he",
        theme="light" if user.theme == "light" else "dark" if user.theme == "dark" else "system",
        must_change_password=user.must_change_password,
        csrf_token=csrf_token,
    )


@router.post("/auth/login", response_model=MeResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: DbDep,
    store: StoreDep,
    audit: AuditDep,
    throttle: Annotated[LoginThrottle, Depends(get_login_throttle)],
) -> MeResponse:
    ip = client_ip(request)
    username = body.username.lower()
    if throttle.is_locked(username, ip):
        audit.record(
            db,
            AuditEvent(
                actor=username,
                action="auth.login",
                outcome="denied",
                source_ip=ip,
                details={"reason": "locked_out"},
            ),
        )
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too_many_attempts")

    result = sign_in(db, get_settings(), username, body.password, remote=ip or "")
    user = result.user
    if user is None:
        throttle.register_failure(username, ip)
        audit.record(
            db,
            AuditEvent(
                actor=username,
                action="auth.login",
                outcome="failure",
                source_ip=ip,
                details={"provider": result.provider, "reason": result.reason[:200]},
            ),
        )
        db.commit()
        # One answer for every failure: no hint whether the user, password or directory failed.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

    throttle.reset(username)
    user.last_login_at = datetime.now(UTC)
    audit.record(
        db,
        AuditEvent(
            actor=user.username,
            actor_id=user.id,
            action="auth.login",
            outcome="success",
            source_ip=ip,
            details={"provider": result.provider, **result.details},
        ),
    )
    db.commit()

    # Session fixation defence: always issue a brand-new id.
    old = request.cookies.get(SESSION_COOKIE)
    if old:
        store.delete(old)
    session_id, data = store.create(user.id)
    _set_session_cookie(response, session_id)
    return _me(user, data.csrf_token)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: DbDep,
    store: StoreDep,
    audit: AuditDep,
    principal: SelfDep,
) -> None:
    store.delete(principal.session_id)
    response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="strict", path="/")
    audit.record(
        db,
        AuditEvent(
            actor=principal.username,
            actor_id=principal.user_id,
            action="auth.logout",
            outcome="success",
            source_ip=client_ip(request),
        ),
    )
    db.commit()


@router.get("/auth/me", response_model=MeResponse)
def me(
    db: DbDep,
    principal: SelfDep,
) -> MeResponse:
    user = db.get(User, principal.user_id)
    if user is None:  # pragma: no cover - guarded by get_principal
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not_authenticated")
    return _me(user, principal.csrf_token)


@router.post("/auth/change-password", response_model=MeResponse)
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    db: DbDep,
    store: StoreDep,
    audit: AuditDep,
    principal: SelfDep,
) -> MeResponse:
    user = db.get(User, principal.user_id)
    if user is None or user.auth_provider != "local":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "not_a_local_account")
    if not verify_password(user.password_hash, body.current_password):
        audit.record(
            db,
            AuditEvent(
                actor=user.username,
                actor_id=user.id,
                action="auth.change_password",
                outcome="failure",
                source_ip=client_ip(request),
            ),
        )
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_current_password")
    if body.new_password == body.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password_unchanged")
    try:
        check_policy(body.new_password, user.username)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password_policy") from exc

    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = datetime.now(UTC)
    audit.record(
        db,
        AuditEvent(
            actor=user.username,
            actor_id=user.id,
            action="auth.change_password",
            outcome="success",
            source_ip=client_ip(request),
        ),
    )
    db.commit()

    # Invalidate every other session of this user, then continue on a fresh one.
    store.delete_all_for_user(user.id)
    session_id, data = store.create(user.id)
    _set_session_cookie(response, session_id)
    return _me(user, data.csrf_token)


@router.patch("/me/preferences", response_model=MeResponse)
def update_preferences(
    body: PreferencesRequest,
    db: DbDep,
    principal: SelfDep,
) -> MeResponse:
    user = db.get(User, principal.user_id)
    if user is None:  # pragma: no cover - guarded by get_principal
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not_authenticated")
    if body.language is not None:
        user.language = body.language
    if body.theme is not None:
        user.theme = body.theme
    db.commit()
    return _me(user, principal.csrf_token)
