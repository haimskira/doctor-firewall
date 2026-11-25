"""Cooperative cancel of a running job: a Redis flag per run that the job checks between steps.

The API sets the flag (:func:`request`); the job asks :func:`requested` at the points where
stopping is safe (never in the middle of an FMC write or one batch's undo). The flag expires
by itself, so a run that never looks at it leaves nothing behind.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from typing import Any

from redis.exceptions import RedisError

log = logging.getLogger(__name__)

FLAG_TTL_SECONDS = 6 * 3600


def key(run_id: int) -> str:
    return f"df:cancel:run:{run_id}"


def request(redis: Any, run_id: int, by: str) -> None:
    redis.set(key(run_id), by[:64], ex=FLAG_TTL_SECONDS)


def requested(redis: Any, run_id: int) -> str | None:
    """Who cancelled the run, or None. An unreachable Redis never cancels anything."""
    try:
        value = redis.get(key(run_id))
    except RedisError:
        log.warning("cancel flag unreadable", extra={"run": run_id})
        return None
    if value is None:
        return None
    return value.decode() if isinstance(value, bytes) else str(value)


def clear(redis: Any, run_id: int) -> None:
    with contextlib.suppress(RedisError):  # it expires by itself
        redis.delete(key(run_id))


def checker(redis: Any, run_id: int | None) -> Callable[[], str | None] | None:
    """A no-argument check for a tracked run (None for an untracked job: nothing to cancel)."""
    if run_id is None:
        return None
    return lambda: requested(redis, run_id)
