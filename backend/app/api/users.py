from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import (
    StrictModel,
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
from app.models.user import User, UserChangeRequest
from app.runtime import get_audit, get_session_store

router = APIRouter(prefix="/api/users", tags=["users"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
AdminDep = Annotated[Principal, Depends(require(Permission.USERS_MANAGE))]

# Two-administrator rule: granting any of these roles, or resetting the password of a holder,
# needs a second active administrator once there is more than one. Bootstrap exception: a fresh
# install has exactly one administrator, and his changes apply immediately.
PRIVILEGED_ROLES = frozenset({Role.ADMIN.value, Role.APPROVER.value, Role.OPTIMIZER.value})
REQUEST_TTL = timedelta(hours=24)


class PasswordResetBody(StrictModel):
    # Ignored (and never stored) when the reset is queued: the approver gets a generated one.
    temporary_password: str | None = None


class ChangeRequestResponse(BaseModel):
    id: int
    kind: str
    target_user_id: int | None
    target_username: str
    payload: dict[str, Any]
    requested_by: str
    requested_at: datetime
    expires_at: datetime
    status: str
    decided_by: str | None
    decided_at: datetime | None


class ApprovalResponse(BaseModel):
    request_id: int
    status: str
    user: UserResponse | None = None
    # Shown once, to the approver, who hands it to the user; must be changed at first sign-in.
    temporary_password: str | None = None


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


def _needs_second_admin(db: Session) -> bool:
    count = db.scalar(
        select(func.count(User.id)).where(
            User.is_active.is_(True), User.roles.contains([Role.ADMIN.value])
        )
    )
    return (count or 0) > 1


def _generate_password(username: str) -> str:
    while True:
        candidate = secrets.token_urlsafe(14) + "-aA1"
        try:
            check_policy(candidate, username)
        except PasswordPolicyError:
            continue
        return candidate


def _to_request_response(row: UserChangeRequest) -> ChangeRequestResponse:
    return ChangeRequestResponse(
        id=row.id,
        kind=row.kind,
        target_user_id=row.target_user_id,
        target_username=row.target_username,
        payload=row.payload,
        requested_by=row.requested_by,
        requested_at=row.requested_at,
        expires_at=row.requested_at + REQUEST_TTL,
        status=row.status,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
    )


def _expire_stale(db: Session) -> None:
    now = datetime.now(UTC)
    stale = db.scalars(
        select(UserChangeRequest).where(
            UserChangeRequest.status == "pending",
            UserChangeRequest.requested_at < now - REQUEST_TTL,
        )
    ).all()
    for row in stale:
        row.status = "expired"
        row.decided_at = now
    db.flush()


def _queue(
    db: Session,
    audit: AuditLog,
    request: Request,
    admin: Principal,
    *,
    kind: str,
    target_user_id: int | None,
    target_username: str,
    payload: dict[str, Any],
) -> JSONResponse:
    _expire_stale(db)
    duplicate = db.scalar(
        select(UserChangeRequest.id).where(
            UserChangeRequest.status == "pending",
            UserChangeRequest.target_username == target_username,
            UserChangeRequest.kind == kind,
        )
    )
    if duplicate is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "request_pending")
    row = UserChangeRequest(
        kind=kind,
        target_user_id=target_user_id,
        target_username=target_username,
        payload=payload,
        requested_by=admin.username,
        status="pending",
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        AuditEvent(
            actor=admin.username,
            actor_id=admin.user_id,
            action="user.request.create",
            outcome="success",
            target=target_username,
            source_ip=client_ip(request),
            details={"request_id": row.id, "kind": kind, "payload": payload},
        ),
    )
    db.commit()
    return JSONResponse(
        {"request_id": row.id, "status": "pending"}, status_code=status.HTTP_202_ACCEPTED
    )


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
) -> UserResponse | JSONResponse:
    username = body.username.lower()
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username_taken")
    local = body.auth_provider == "local"
    role_values = sorted({r.value for r in body.roles})
    if PRIVILEGED_ROLES & set(role_values) and _needs_second_admin(db):
        return _queue(
            db,
            audit,
            request,
            admin,
            kind="create",
            target_user_id=None,
            target_username=username,
            payload={
                "roles": role_values,
                "provider": body.auth_provider,
                "display_name": body.display_name,
            },
        )
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
        roles=role_values,
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
) -> UserResponse | JSONResponse:
    user = _get_user(db, user_id)
    changes: dict[str, object] = {}
    new_roles = sorted({r.value for r in body.roles}) if body.roles is not None else user.roles
    new_active = body.is_active if body.is_active is not None else user.is_active
    loses_admin = Role.ADMIN.value in user.roles and (
        Role.ADMIN.value not in new_roles or not new_active
    )
    if loses_admin and _other_active_admins(db, user.id) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "last_admin")
    if user.id == admin.user_id and set(new_roles) != set(user.roles):
        # Raising one's own rights (or dropping them by mistake) takes another administrator.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot_change_own_roles")
    granted = (PRIVILEGED_ROLES & set(new_roles)) - set(user.roles)
    if granted and _needs_second_admin(db):
        payload: dict[str, Any] = {"roles": new_roles}
        if body.display_name is not None:
            payload["display_name"] = body.display_name
        if body.is_active is not None:
            payload["is_active"] = body.is_active
        return _queue(
            db,
            audit,
            request,
            admin,
            kind="roles",
            target_user_id=user.id,
            target_username=user.username,
            payload=payload,
        )

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
    body: PasswordResetBody,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    admin: AdminDep,
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> UserResponse | JSONResponse:
    user = _get_user(db, user_id)
    if user.auth_provider != "local":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "not_a_local_account")
    if PRIVILEGED_ROLES & set(user.roles) and _needs_second_admin(db):
        return _queue(
            db,
            audit,
            request,
            admin,
            kind="password_reset",
            target_user_id=user.id,
            target_username=user.username,
            payload={},
        )
    if body.temporary_password is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "password_required")
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


@router.get("/requests", response_model=list[ChangeRequestResponse])
def list_requests(db: DbDep, _: AdminDep) -> list[ChangeRequestResponse]:
    _expire_stale(db)
    db.commit()
    rows = db.scalars(
        select(UserChangeRequest)
        .where(UserChangeRequest.status == "pending")
        .order_by(UserChangeRequest.id)
    )
    return [_to_request_response(r) for r in rows]


def _load_decidable(db: Session, request_id: int, admin: Principal) -> UserChangeRequest:
    _expire_stale(db)
    row = db.scalar(
        select(UserChangeRequest).where(UserChangeRequest.id == request_id).with_for_update()
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if row.status == "expired":
        db.commit()  # keep the expiry mark
        raise HTTPException(status.HTTP_409_CONFLICT, "request_expired")
    if row.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "request_not_pending")
    if row.requested_by == admin.username:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot_decide_own_request")
    if row.target_user_id is not None and row.target_user_id == admin.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot_decide_own_request")
    return row


def _audit_decision(
    db: Session,
    audit: AuditLog,
    request: Request,
    admin: Principal,
    row: UserChangeRequest,
    action: str,
) -> None:
    audit.record(
        db,
        AuditEvent(
            actor=admin.username,
            actor_id=admin.user_id,
            action=action,
            outcome="success",
            target=row.target_username,
            source_ip=client_ip(request),
            details={"request_id": row.id, "kind": row.kind, "requested_by": row.requested_by},
        ),
    )


@router.post("/requests/{request_id}/reject", response_model=ApprovalResponse)
def reject_request(
    request_id: int, request: Request, db: DbDep, audit: AuditDep, admin: AdminDep
) -> ApprovalResponse:
    row = _load_decidable(db, request_id, admin)
    row.status = "rejected"
    row.decided_by = admin.username
    row.decided_at = datetime.now(UTC)
    _audit_decision(db, audit, request, admin, row, "user.request.reject")
    db.commit()
    return ApprovalResponse(request_id=row.id, status="rejected")


def _apply_create(db: Session, row: UserChangeRequest) -> tuple[User, str | None]:
    provider = str(row.payload["provider"])
    if db.scalar(select(User.id).where(User.username == row.target_username)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username_taken")
    temporary = _generate_password(row.target_username) if provider == "local" else None
    user = User(
        username=row.target_username,
        display_name=str(row.payload.get("display_name", "")),
        auth_provider=provider,
        password_hash=hash_password(temporary) if temporary else None,
        roles=sorted(str(r) for r in row.payload["roles"]),
        is_active=True,
        must_change_password=provider == "local",
        language="he",
    )
    db.add(user)
    db.flush()
    return user, temporary


def _apply_roles(db: Session, row: UserChangeRequest, user: User) -> bool:
    """Apply a queued role change; True when the user was deactivated (sessions must go)."""
    new_roles = sorted(str(r) for r in row.payload["roles"])
    new_active = bool(row.payload.get("is_active", user.is_active))
    loses_admin = Role.ADMIN.value in user.roles and (
        Role.ADMIN.value not in new_roles or not new_active
    )
    if loses_admin and _other_active_admins(db, user.id) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "last_admin")
    deactivated = user.is_active and not new_active
    user.roles = new_roles
    if "display_name" in row.payload:
        user.display_name = str(row.payload["display_name"])
    user.is_active = new_active
    return deactivated


@router.post("/requests/{request_id}/approve", response_model=ApprovalResponse)
def approve_request(
    request_id: int,
    request: Request,
    db: DbDep,
    audit: AuditDep,
    admin: AdminDep,
    store: Annotated[SessionStore, Depends(get_session_store)],
) -> ApprovalResponse:
    row = _load_decidable(db, request_id, admin)
    temporary: str | None = None
    kill_sessions = False
    if row.kind == "create":
        user, temporary = _apply_create(db, row)
    else:
        found = db.get(User, row.target_user_id) if row.target_user_id is not None else None
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
        user = found
        if row.kind == "roles":
            kill_sessions = _apply_roles(db, row, user)
        else:
            if user.auth_provider != "local":
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "not_a_local_account")
            temporary = _generate_password(user.username)
            user.password_hash = hash_password(temporary)
            user.must_change_password = True
            kill_sessions = True
    row.status = "approved"
    row.decided_by = admin.username
    row.decided_at = datetime.now(UTC)
    row.target_user_id = user.id
    _audit_decision(db, audit, request, admin, row, "user.request.approve")
    db.commit()
    if kill_sessions:
        store.delete_all_for_user(user.id)
    return ApprovalResponse(
        request_id=row.id,
        status="approved",
        user=_to_response(user),
        temporary_password=temporary,
    )
