"""RQ worker entry point: ``python -m app.workers.worker``.

Hardening on top of stock RQ:

* JSON serializer only, so job payloads are never unpickled.
* An allow-list of importable job functions: a job naming anything else is
  rejected before import, even if someone manages to write to Redis.
* The Redis password is read from the Docker secret, never passed on the command line.
"""

from __future__ import annotations

import logging

from rq import Worker
from rq.job import Job
from rq.queue import Queue
from rq.serializers import JSONSerializer

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.runtime import get_redis
from app.workers.jobs import ALLOWED_JOBS
from app.workers.queues import QueueName, get_queue

log = logging.getLogger(__name__)


class JobNotAllowedError(RuntimeError):
    pass


REJECTED_MESSAGE = "job function is not allow-listed"


class AllowListWorker(Worker):
    def execute_job(self, job: Job, queue: Queue) -> None:
        # Checked in the parent, before forking: a rejected job never runs any code
        # and is recorded as failed with an explicit reason.
        if job.func_name not in ALLOWED_JOBS:
            log.error("rejected job outside allow-list", extra={"job_id": job.id})
            self.handle_job_failure(job, queue, exc_string=REJECTED_MESSAGE)
            return
        super().execute_job(job, queue)

    def perform_job(self, job: Job, queue: Queue) -> bool:
        # Second line of defence inside the work horse.
        if job.func_name not in ALLOWED_JOBS:
            raise JobNotAllowedError(REJECTED_MESSAGE)
        return super().perform_job(job, queue)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    redis = get_redis()
    queues = [get_queue(name, redis) for name in QueueName]
    worker = AllowListWorker(queues, connection=redis, serializer=JSONSerializer)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
