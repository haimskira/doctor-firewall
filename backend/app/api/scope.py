"""Which policies a view covers: one chosen policy, or every policy a device enforces."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Query
from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.models.inventory import ClusterPolicy

PolicyQuery = Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


def enforced(snapshot_id: int) -> Any:
    """Subquery: the policies some cluster of the snapshot enforces."""
    return select(ClusterPolicy.policy_fmc_id).where(ClusterPolicy.snapshot_id == snapshot_id)


def is_enforced(db: Session, snapshot_id: int, policy: str) -> bool:
    return (
        db.scalar(
            select(ClusterPolicy.policy_fmc_id)
            .where(ClusterPolicy.snapshot_id == snapshot_id, ClusterPolicy.policy_fmc_id == policy)
            .limit(1)
        )
        is not None
    )


def policy_or_shared(column: InstrumentedAttribute[Any], policy: str | None) -> ColumnElement[bool]:
    """Items of one policy plus the shared ones (objects belong to every policy); all if None."""
    if policy is None:
        return column.is_not(None) | column.is_(None)
    return or_(column == policy, column.is_(None))
