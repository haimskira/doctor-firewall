"""Read-only API tokens for other systems.

A token is ``dfk_<prefix>_<secret>``: 8 + 40 characters of URL-safe randomness. Only its SHA-256
is stored; the token itself is shown once, when it is created. A request carrying
``Authorization: Bearer dfk_...`` acts as the token's owner, but:

* only with the owner's *read* permissions (``policy:read``, ``audit:read``) — never more than
  the owner has, and never a write: writes stay in the UI, behind four-eyes approval;
* only for GET / HEAD requests;
* only while the owner is active and the token is neither expired nor revoked.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.rbac import Permission
from app.models.user import ApiToken

TOKEN_PREFIX = "dfk_"  # noqa: S105  # nosec B105 - a public marker, not a secret
READ_PERMISSIONS = frozenset({Permission.POLICY_READ, Permission.AUDIT_READ})
MAX_DAYS = 365
TOUCH_EVERY = timedelta(minutes=1)  # last_used_at is written at most this often


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> tuple[str, str]:
    """(token, prefix): the token goes to its owner once; the prefix identifies it in lists."""
    prefix = secrets.token_hex(4)
    return f"{TOKEN_PREFIX}{prefix}_{secrets.token_urlsafe(30)}", prefix


def lookup(db: Session, token: str, now: datetime | None = None) -> ApiToken | None:
    """The live token row for a presented token (constant-time compare on the hash)."""
    if not token.startswith(TOKEN_PREFIX) or len(token) > 128:
        return None
    wanted = digest(token)
    row = db.scalar(select(ApiToken).where(ApiToken.token_hash == wanted))
    if row is None or not hmac.compare_digest(row.token_hash, wanted):
        return None
    now = now or datetime.now(UTC)
    if row.revoked_at is not None or row.expires_at <= now:
        return None
    if row.last_used_at is None or now - row.last_used_at >= TOUCH_EVERY:
        row.last_used_at = now
        db.commit()
    return row


def expiry(days: int, now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)) + timedelta(days=max(1, min(days, MAX_DAYS)))
