"""Queue definitions. Every queue uses RQ's JSON serializer — never pickle."""

from __future__ import annotations

from enum import StrEnum

from redis import Redis
from rq import Queue
from rq.serializers import JSONSerializer


class QueueName(StrEnum):
    COLLECT = "collect"  # FMC reads (one connection at a time per snapshot)
    ANALYSIS = "analysis"  # CPU-heavy analysis of stored snapshots
    MAINTENANCE = "maintenance"
    ENFORCE = "enforce"  # approved FMC writes + deploys (one batch at a time per FMC)


def get_queue(name: QueueName, connection: Redis) -> Queue:
    return Queue(name.value, connection=connection, serializer=JSONSerializer)
