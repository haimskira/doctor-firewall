"""Server-side sessions in Redis.

* The browser holds only an opaque random id in a ``__Host-`` cookie (HttpOnly,
  Secure, SameSite=Strict). No token is ever exposed to JavaScript storage.
* Redis stores the session under SHA-256(id), so a Redis dump does not yield
  usable cookies.
* Each session has an idle timeout and an absolute lifetime.
* A per-session CSRF token is returned by ``/api/auth/me`` and must be echoed in
  the ``X-CSRF-Token`` header on every state-changing request.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redis import Redis

SESSION_COOKIE = "__Host-df_session"
_PREFIX = "df:sess:"
_USER_INDEX = "df:user_sess:"


def _key(session_id: str) -> str:
    return _PREFIX + hashlib.sha256(session_id.encode()).hexdigest()


@dataclass(frozen=True)
class SessionData:
    user_id: int
    csrf_token: str
    created_at: datetime
    last_seen: datetime


class SessionStore:
    def __init__(self, redis: Redis, idle: timedelta, absolute: timedelta) -> None:
        self._redis = redis
        self._idle = idle
        self._absolute = absolute

    def create(self, user_id: int) -> tuple[str, SessionData]:
        session_id = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        data = SessionData(user_id, secrets.token_urlsafe(32), now, now)
        key = _key(session_id)
        pipe = self._redis.pipeline()
        pipe.set(key, self._dump(data), ex=self._idle)
        pipe.sadd(_USER_INDEX + str(user_id), key)
        pipe.expire(_USER_INDEX + str(user_id), self._absolute)
        pipe.execute()
        return session_id, data

    def get(self, session_id: str) -> SessionData | None:
        """Return a live session and slide its idle timeout, or ``None``."""
        if not session_id or len(session_id) > 128:
            return None
        key = _key(session_id)
        raw = self._redis.get(key)
        if raw is None:
            return None
        data = self._load(raw)
        now = datetime.now(UTC)
        if data is None or now - data.created_at > self._absolute:
            self._redis.delete(key)
            return None
        remaining_absolute = self._absolute - (now - data.created_at)
        refreshed = SessionData(data.user_id, data.csrf_token, data.created_at, now)
        self._redis.set(key, self._dump(refreshed), ex=min(self._idle, remaining_absolute))
        return refreshed

    def delete(self, session_id: str) -> None:
        self._redis.delete(_key(session_id))

    def delete_all_for_user(self, user_id: int) -> None:
        index = _USER_INDEX + str(user_id)
        keys = list(self._redis.smembers(index))
        if keys:
            self._redis.delete(*keys)
        self._redis.delete(index)

    @staticmethod
    def _dump(data: SessionData) -> str:
        return json.dumps(
            {
                "uid": data.user_id,
                "csrf": data.csrf_token,
                "created": data.created_at.isoformat(),
                "seen": data.last_seen.isoformat(),
            }
        )

    @staticmethod
    def _load(raw: bytes | str) -> SessionData | None:
        try:
            doc = json.loads(raw)
            return SessionData(
                user_id=int(doc["uid"]),
                csrf_token=str(doc["csrf"]),
                created_at=datetime.fromisoformat(doc["created"]),
                last_seen=datetime.fromisoformat(doc["seen"]),
            )
        except (ValueError, KeyError, TypeError):
            return None
