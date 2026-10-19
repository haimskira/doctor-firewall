"""Queue definitions. Every queue uses RQ's JSON serializer — never pickle."""

from __future__ import annotations

from enum import StrEnum

from redis import Redis
from rq import Queue
from rq.serializers import JSONSerializer


class QueueName(StrEnum):
    MAINTENANCE = "maintenance"


def get_queue(name: QueueName, connection: Redis) -> Queue:
    return Queue(name.value, connection=connection, serializer=JSONSerializer)
