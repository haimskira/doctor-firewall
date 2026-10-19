from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password, needs_rehash, verify_password
from app.auth.providers.base import AuthenticatedIdentity
from app.models.user import User


class LocalProvider:
    """Username/password stored in the local DB (Argon2id hashes)."""

    name = "local"

    def authenticate(
        self, session: Session, username: str, password: str
    ) -> AuthenticatedIdentity | None:
        user = session.scalar(
            select(User).where(User.username == username.lower(), User.auth_provider == "local")
        )
        # verify_password runs the full hash even when the user does not exist.
        if not verify_password(user.password_hash if user else None, password):
            return None
        if user is None or not user.is_active:
            return None
        if user.password_hash and needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
        return AuthenticatedIdentity(user_id=user.id, username=user.username)
