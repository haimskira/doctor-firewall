"""The API for other systems: read-only tokens and the OpenAPI document of the read API.

Everything another system can pull is a GET endpoint of this API, with the same permission
checks as the UI. Tokens are created in the UI (a signed-in session, never with a token) and are
shown once; the OpenAPI document lists the GET operations only (writes stay in the UI).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import StrictModel
from app.audit.chain import AuditEvent, AuditLog
from app.auth import tokens
from app.auth.deps import Principal, client_ip, require, require_authenticated
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.user import ApiToken, User
from app.runtime import get_audit

router = APIRouter(prefix="/api", tags=["developer"])

DbDep = Annotated[Session, Depends(get_db)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
SelfDep = Annotated[Principal, Depends(require_authenticated())]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
MAX_TOKENS = 20  # live tokens per user


class TokenIn(StrictModel):
    name: Annotated[str, Field(min_length=3, max_length=64, pattern=r"^[\w .:/-]+$")]
    days: Annotated[int, Field(ge=1, le=tokens.MAX_DAYS)] = 90


class TokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    owner: str
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class TokenCreated(TokenOut):
    token: str  # shown once


def _out(row: ApiToken, owner: str) -> TokenOut:
    return TokenOut(
        id=row.id,
        name=row.name,
        prefix=row.prefix,
        owner=owner,
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
    )


def _audit(
    audit: AuditLog, db: Session, who: Principal, request: Request, action: str, row: ApiToken
) -> None:
    audit.record(
        db,
        AuditEvent(
            actor=who.username,
            actor_id=who.user_id,
            action=action,
            outcome="success",
            target=f"token {row.prefix}",
            source_ip=client_ip(request),
            details={"token_id": row.id, "name": row.name, "owner_id": row.user_id},
        ),
    )


@router.get("/tokens", response_model=list[TokenOut])
def list_tokens(db: DbDep, who: SelfDep) -> list[TokenOut]:
    """Your tokens (an administrator sees everyone's)."""
    query = select(ApiToken, User.username).join(User, User.id == ApiToken.user_id)
    if Permission.USERS_MANAGE not in who.permissions:
        query = query.where(ApiToken.user_id == who.user_id)
    return [_out(row, owner) for row, owner in db.execute(query.order_by(ApiToken.id.desc()))]


@router.post("/tokens", response_model=TokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(
    body: TokenIn, request: Request, db: DbDep, audit: AuditDep, who: SelfDep
) -> TokenCreated:
    """A new read-only token for another system; the token is in this answer only."""
    if who.token_id is not None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token_read_only")
    live = db.scalars(
        select(ApiToken.id).where(ApiToken.user_id == who.user_id, ApiToken.revoked_at.is_(None))
    ).all()
    if len(live) >= MAX_TOKENS:
        raise HTTPException(status.HTTP_409_CONFLICT, "too_many_tokens")
    token, prefix = tokens.new_token()
    row = ApiToken(
        user_id=who.user_id,
        name=body.name.strip(),
        prefix=prefix,
        token_hash=tokens.digest(token),
        expires_at=tokens.expiry(body.days),
    )
    db.add(row)
    db.flush()
    _audit(audit, db, who, request, "api_token.created", row)
    db.commit()
    db.refresh(row)
    return TokenCreated(**_out(row, who.username).model_dump(), token=token)


@router.delete("/tokens/{token_id}", response_model=TokenOut)
def revoke_token(
    token_id: int, request: Request, db: DbDep, audit: AuditDep, who: SelfDep
) -> TokenOut:
    row = db.get(ApiToken, token_id)
    mine = row is not None and row.user_id == who.user_id
    if row is None or not (mine or Permission.USERS_MANAGE in who.permissions):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(row.expires_at.tzinfo)
        _audit(audit, db, who, request, "api_token.revoked", row)
        db.commit()
    owner = db.get(User, row.user_id)
    return _out(row, owner.username if owner else "?")


@router.get("/openapi.json", response_model=dict[str, Any])
def openapi(request: Request, _: ReaderDep) -> dict[str, Any]:
    """The read API (every GET operation) as OpenAPI 3, for the explorer and for clients."""
    full = request.app.openapi()
    paths: dict[str, Any] = {}
    for path, ops in full.get("paths", {}).items():
        if path in ("/api/openapi.json",) or path.startswith("/api/tokens"):
            continue
        reads = {m: op for m, op in ops.items() if m == "get"}
        if reads:
            paths[path] = reads
    return {
        **full,
        "info": {
            "title": "Doctor Firewall — read API",
            "version": full.get("info", {}).get("version", ""),
            "description": (
                "Every GET endpoint of the system. Authenticate with a signed-in browser session "
                "or with `Authorization: Bearer <token>` (API → tokens). Tokens are read-only: "
                "changes to the firewall go through the UI and its four-eyes approval."
            ),
        },
        "paths": paths,
        "components": {
            **full.get("components", {}),
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        },
        "security": [{"bearer": []}],
    }
