"""Periodic job scheduler: ``python -m app.workers.scheduler``.

A deliberately small interval scheduler instead of rq-scheduler / rq cron (the
latter enqueue with RQ's default pickle serializer). Each tick, for every due
schedule, it claims the time slot with Redis ``SET NX`` (so several scheduler
replicas never double-enqueue) and enqueues the job with the JSON serializer.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import FrameType

from redis import Redis

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.runtime import get_redis
from app.workers import jobs
from app.workers.queues import QueueName, get_queue

log = logging.getLogger(__name__)

TICK_SECONDS = 15
_SLOT_PREFIX = "df:sched:"


@dataclass(frozen=True)
class Schedule:
    name: str
    func: Callable[[], object]
    queue: QueueName
    every_seconds: int


SCHEDULES: tuple[Schedule, ...] = (
    Schedule("verify_audit_chain", jobs.verify_audit_chain, QueueName.MAINTENANCE, 3600),
)


def run_due(redis: Redis, now: float, schedules: tuple[Schedule, ...] = SCHEDULES) -> list[str]:
    """Enqueue every schedule whose current slot has not been claimed yet."""
    enqueued: list[str] = []
    for sched in schedules:
        slot = int(now // sched.every_seconds)
        claimed = redis.set(
            f"{_SLOT_PREFIX}{sched.name}:{slot}", "1", nx=True, ex=sched.every_seconds * 2
        )
        if claimed:
            get_queue(sched.queue, redis).enqueue(sched.func, job_timeout=sched.every_seconds)
            enqueued.append(sched.name)
            log.info("scheduled job enqueued", extra={"schedule": sched.name, "slot": slot})
    return enqueued


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    redis = get_redis()
    stop = threading.Event()

    def _stop(signum: int, _frame: FrameType | None) -> None:
        log.info("scheduler stopping", extra={"signal": signum})
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("scheduler started", extra={"schedules": [s.name for s in SCHEDULES]})
    while not stop.is_set():
        run_due(redis, time.time())
        stop.wait(TICK_SECONDS)


if __name__ == "__main__":
    main()
