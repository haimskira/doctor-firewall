"""Which policies a view covers: one chosen policy, or every policy a device enforces.

An access policy is a world of its own (its rules, linked policies and the objects they use);
findings and recommendations carry the policies they belong to (``policy_ids``, see
:mod:`app.analysis.policy_scope`).
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Query
from sqlalchemy import BigInteger, ColumnElement, case, func, select, true
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.analysis import policy_scope
from app.models.inventory import ClusterPolicy, Snapshot
from app.models.recommendations import Recommendation

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


def in_policy(column: InstrumentedAttribute[Any], policy: str | None) -> ColumnElement[bool]:
    """Items belonging to one policy (``column``: a ``policy_ids`` array); all if None."""
    if policy is None:
        return true()
    return column.contains([policy])


def ace_delta_in(policy: str | None) -> Any:
    """A recommendation's ACE change on one policy's rules: a compacted group serves every
    policy using it, and each policy's view counts its own part."""
    if policy is None:
        return Recommendation.ace_delta
    part = Recommendation.preview["compact"]["ace_by_policy"][policy].astext.cast(BigInteger)
    return case(
        (Recommendation.kind == "compact_group", func.coalesce(part, Recommendation.ace_delta)),
        else_=Recommendation.ace_delta,
    )


def ensure_scoped(db: Session, snapshot_id: int, policy: str | None) -> None:
    """A snapshot analysed before items carried their policies gets them now (once)."""
    if policy is None:
        return
    snap = db.get(Snapshot, snapshot_id)
    if snap is None or snap.analyzed_at is None or "objects_by_policy" in (snap.stats or {}):
        return
    policy_scope.assign(db, snapshot_id)
    db.commit()
