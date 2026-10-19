from __future__ import annotations

from datetime import UTC, datetime, timedelta

import fakeredis
import pytest

from app.auth.sessions import SessionStore, _key
from app.auth.throttle import LoginThrottle


@pytest.fixture
def redis() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis()


def test_session_lifecycle(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    sid, data = store.create(7)
    assert len(sid) >= 40
    got = store.get(sid)
    assert got is not None
    assert got.user_id == 7
    assert got.csrf_token == data.csrf_token
    # Only the hash of the id is stored.
    assert all(sid.encode() not in k for k in redis.keys("*"))
    store.delete(sid)
    assert store.get(sid) is None


def test_unknown_and_oversized_ids(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    assert store.get("nope") is None
    assert store.get("") is None
    assert store.get("x" * 500) is None


def test_absolute_expiry(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    sid, data = store.create(1)
    old = data.created_at - timedelta(hours=9)
    redis.set(
        _key(sid),
        f'{{"uid": 1, "csrf": "c", "created": "{old.isoformat()}", "seen": "{old.isoformat()}"}}',
    )
    assert store.get(sid) is None
    assert redis.get(_key(sid)) is None


def test_idle_ttl_is_set(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    sid, _ = store.create(1)
    assert 0 < redis.ttl(_key(sid)) <= 30 * 60


def test_corrupt_session_rejected(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    sid, _ = store.create(1)
    redis.set(_key(sid), "{not json")
    assert store.get(sid) is None


def test_delete_all_for_user(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    a, _ = store.create(5)
    b, _ = store.create(5)
    other, _ = store.create(6)
    store.delete_all_for_user(5)
    assert store.get(a) is None
    assert store.get(b) is None
    assert store.get(other) is not None
    store.delete_all_for_user(99)  # no sessions: no error


def test_sessions_get_slides_last_seen(redis: fakeredis.FakeRedis) -> None:
    store = SessionStore(redis, idle=timedelta(minutes=30), absolute=timedelta(hours=8))
    sid, data = store.create(1)
    got = store.get(sid)
    assert got is not None
    assert got.last_seen >= data.last_seen
    assert got.created_at == data.created_at
    assert got.last_seen <= datetime.now(UTC)


def test_throttle_locks_user_after_max_failures(redis: fakeredis.FakeRedis) -> None:
    throttle = LoginThrottle(redis, max_failures=3, lockout=timedelta(minutes=15))
    for _ in range(2):
        throttle.register_failure("Alice", "10.0.0.1")
    assert not throttle.is_locked("alice", "10.0.0.1")
    throttle.register_failure("alice", "10.0.0.2")
    assert throttle.is_locked("ALICE", "10.9.9.9")  # per-user, any IP
    throttle.reset("alice")
    assert not throttle.is_locked("alice", "10.0.0.3")


def test_throttle_locks_ip_after_spray(redis: fakeredis.FakeRedis) -> None:
    throttle = LoginThrottle(redis, max_failures=3, lockout=timedelta(minutes=15))
    for i in range(12):
        throttle.register_failure(f"user{i}", "10.0.0.66")
    assert throttle.is_locked("fresh-user", "10.0.0.66")
    assert not throttle.is_locked("fresh-user", "10.0.0.67")
