"""Login brute-force protection: per-username and per-source-IP failure counters."""

from __future__ import annotations

import hashlib
from datetime import timedelta

from redis import Redis
from redis.exceptions import RedisError

_PREFIX = "df:loginfail:"
_TRUST_PREFIX = "df:logintrust:"
# A client address that signed in as a user within this window is not locked out of that
# account by someone else's failures (otherwise anyone can keep "admin" locked forever).
TRUST_TTL = timedelta(days=30)


def _key(kind: str, value: str) -> str:
    # Hash the identifier so usernames/IPs are not stored in clear in Redis keys.
    return f"{_PREFIX}{kind}:{hashlib.sha256(value.encode()).hexdigest()}"


def _trust_key(username: str, source_ip: str) -> str:
    digest = hashlib.sha256(f"{username.lower()}|{source_ip}".encode()).hexdigest()
    return f"{_TRUST_PREFIX}{digest}"


def remember_login(redis: Redis, username: str, source_ip: str) -> None:
    """Remember a successful (user, IP) pair; best effort, never blocks a sign-in."""
    if not source_ip:
        return
    try:
        redis.set(_trust_key(username, source_ip), "1", ex=TRUST_TTL)
    except RedisError:  # the trust list is an optimisation, not a gate
        return


class LoginThrottle:
    def __init__(self, redis: Redis, max_failures: int, lockout: timedelta) -> None:
        self._redis = redis
        self._max = max_failures
        self._lockout = lockout

    def _keys(self, username: str, source_ip: str) -> tuple[str, str]:
        # The IP limit is looser: many users may share a NAT/jump host.
        return _key("user", username.lower()), _key("ip", source_ip)

    def is_locked(self, username: str, source_ip: str, *, honour_trust: bool = True) -> bool:
        """``honour_trust``: sign-in only — guessing the current password of a signed-in
        session (change-password) is never exempt."""
        user_key, ip_key = self._keys(username, source_ip)
        user_fails, ip_fails, trusted = self._redis.mget(
            user_key, ip_key, _trust_key(username, source_ip)
        )
        if int(ip_fails or 0) >= self._max * 4:
            return True
        # The per-user lock does not apply to an address that already signed in as this user.
        return int(user_fails or 0) >= self._max and (trusted is None or not honour_trust)

    @property
    def max_failures(self) -> int:
        return self._max

    def register_failure(self, username: str, source_ip: str) -> int:
        """Count a failure; returns the user's failures within the lockout window."""
        pipe = self._redis.pipeline()
        for key in self._keys(username, source_ip):
            pipe.incr(key)
            pipe.expire(key, self._lockout)
        results = pipe.execute()
        return int(results[0])

    def reset(self, username: str, source_ip: str | None = None) -> None:
        self._redis.delete(_key("user", username.lower()))
        if source_ip:
            remember_login(self._redis, username, source_ip)
