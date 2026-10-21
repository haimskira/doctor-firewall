from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import (
    PasswordResetRequest,
    UserCreateRequest,
    UserResponse,
    UserUpdateRequest,
)
from app.audit.chain import AuditEvent, AuditLog
from app.auth.deps import Principal, client_ip, require
from app.auth.passwords import PasswordPolicyError, check_policy, hash_password
from app.auth.rbac import Permission, Role, parse_roles
from app.auth.sessions import SessionStore
from app.db.session import get_db
from app.models.user import User
from app.runtime import get_audit, get_session_store

router = APIRouter(prefix="/api/users", tags=["users"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
AdminDep = Annotated[Principal, Depends(require(Permission.USERS_MANAGE))]


def _to_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        auth_provider=user.auth_provider,
        roles=sorted(parse_roles(user.roles)),
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        language="en" if user.language == "en" else "he",
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _check_password(password: str, username: str) -> None:
    try:
        check_policy(password, username)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password_policy") from exc


def _other_active_admins(db: Session, user_id: int) -> int:
    count = db.scalar(
        select(func.count(User.id)).where(
            User.id != user_id,
            User.is_active.is_(True),
            User.roles.contains([Role.ADMIN.value]),
        )
    )
    return count or 0


def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return user


@router.get("", response_model=list[UserResponse])
def list_users(db: DbDep, _: AdminDep) -> list[UserResponse]:
    return [_to_response(u) for u in db.scalars(select(User).order_by(User.username))]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest, request: Request, db: DbDep, audit: AuditDep, admin: AdminDep
) -> UserResponse:
    username = body.username.lower()
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username_taken")
    local = body.auth_provider == "local"
    if local != (body.temporary_password is not None):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "password_required" if local else "password_not_allowed",
        )
    if body.temporary_password is not None:
        _check_password(body.temporary_password, username)
    user = User(
        username=username,
        display_name=body.display_name,
        auth_provider=body.auth_provider,
        password_hash=hash_password(body.temporary_password) if body.temporary_password else None,
        roles=sorted({r.value for r in body.roles}),
        is_active=True,
        must_change_password=local,
        language="he",
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        AuditEvent(
            actor=admin.username,
            actor_id=admin.user_id,
            action="user.create",
            outcome="success",
            target=username,
            source_ip=client_ip(request),
            details={"roles": user.roles, "provider": user.auth_provider},
        ),
    )
    db.commit()
    return _to_response(user)


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    body: UserUpdateRequest,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    admin: AdminDep,
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> UserResponse:
    user = _get_user(db, user_id)
    changes: dict[str, object] = {}
    new_roles = sorted({r.value for r in body.roles}) if body.roles is not None else user.roles
    new_active = body.is_active if body.is_active is not None else user.is_active
    loses_admin = Role.ADMIN.value in user.roles and (
        Role.ADMIN.value not in new_roles or not new_active
    )
    if loses_admin and _other_active_admins(db, user.id) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "last_admin")

    if body.display_name is not None and body.display_name != user.display_name:
        user.display_name = body.display_name
        changes["display_name"] = True
    if new_roles != user.roles:
        changes["roles"] = {"from": list(user.roles), "to": new_roles}
        user.roles = new_roles
    if new_active != user.is_active:
        changes["is_active"] = new_active
        user.is_active = new_active

    if changes:
        audit.record(
            db,
            AuditEvent(
                actor=admin.username,
                actor_id=admin.user_id,
                action="user.update",
                outcome="success",
                target=user.username,
                source_ip=client_ip(request),
                details=changes,
            ),
        )
    db.commit()
    if "is_active" in changes and not user.is_active:
        store.delete_all_for_user(user.id)
    return _to_response(user)


@router.post("/{user_id}/reset-password", response_model=UserResponse)
def reset_password(
    user_id: int,
    body: PasswordResetRequest,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    admin: AdminDep,
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> UserResponse:
    user = _get_user(db, user_id)
    if user.auth_provider != "local":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "not_a_local_account")
    _check_password(body.temporary_password, user.username)
    user.password_hash = hash_password(body.temporary_password)
    user.must_change_password = True
    audit.record(
        db,
        AuditEvent(
            actor=admin.username,
            actor_id=admin.user_id,
            action="user.reset_password",
            outcome="success",
            target=user.username,
            source_ip=client_ip(request),
        ),
    )
    db.commit()
    store.delete_all_for_user(user.id)
    return _to_response(user)
