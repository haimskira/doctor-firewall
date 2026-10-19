"""Login brute-force protection: per-username and per-source-IP failure counters."""

from __future__ import annotations

import hashlib
from datetime import timedelta

from redis import Redis

_PREFIX = "df:loginfail:"


def _key(kind: str, value: str) -> str:
    # Hash the identifier so usernames/IPs are not stored in clear in Redis keys.
    return f"{_PREFIX}{kind}:{hashlib.sha256(value.encode()).hexdigest()}"


class LoginThrottle:
    def __init__(self, redis: Redis, max_failures: int, lockout: timedelta) -> None:
        self._redis = redis
        self._max = max_failures
        self._lockout = lockout

    def _keys(self, username: str, source_ip: str) -> tuple[str, str]:
        # The IP limit is looser: many users may share a NAT/jump host.
        return _key("user", username.lower()), _key("ip", source_ip)

    def is_locked(self, username: str, source_ip: str) -> bool:
        user_key, ip_key = self._keys(username, source_ip)
        user_fails, ip_fails = self._redis.mget(user_key, ip_key)
        return int(user_fails or 0) >= self._max or int(ip_fails or 0) >= self._max * 4

    def register_failure(self, username: str, source_ip: str) -> None:
        pipe = self._redis.pipeline()
        for key in self._keys(username, source_ip):
            pipe.incr(key)
            pipe.expire(key, self._lockout)
        pipe.execute()

    def reset(self, username: str) -> None:
        self._redis.delete(_key("user", username.lower()))
