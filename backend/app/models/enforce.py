"""Phase 5: changesets and their batches (the only path that writes to the FMC).

A changeset is built from accepted recommendations of one snapshot; it keeps its own copy of
every plan, so deleting the snapshot (retention) does not change what was approved. It is cut
into batches that never exceed the per-cluster deploy limit. Each batch is approved
separately by an approver who is not the changeset's author.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

CHANGESET_STATUSES = ("open", "in_progress", "completed", "failed", "cancelled")
BATCH_STATUSES = (
    "pending",
    "approved",
    "running",
    "deployed",
    "failed",
    "rolled_back",
    "cancelled",
)


def _in(values: tuple[str, ...]) -> str:
    return ",".join(f"'{v}'" for v in values)


class Changeset(Base):
    __tablename__ = "changesets"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(CHANGESET_STATUSES)})", name="status_known"),
        CheckConstraint("deploy_limit > 0", name="deploy_limit_positive"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    connection_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("fmc_connections.id", ondelete="SET NULL")
    )
    snapshot_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("snapshots.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    ticket_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    # The smallest deploy limit of the clusters it touches, and whether all were verified.
    deploy_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    deploy_limit_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class ChangesetItem(Base):
    __tablename__ = "changeset_items"
    __table_args__ = (UniqueConstraint("changeset_id", "fingerprint", name="item_once"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    changeset_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("changesets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    batch_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    policy_fmc_id: Mapped[str | None] = mapped_column(String(64))
    plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    op_count: Mapped[int] = mapped_column(Integer, nullable=False)


class Batch(Base):
    __tablename__ = "changeset_batches"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(BATCH_STATUSES)})", name="status_known"),
        UniqueConstraint("changeset_id", "seq", name="batch_seq"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    changeset_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("changesets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    op_count: Mapped[int] = mapped_column(Integer, nullable=False)
    deploy_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    clusters: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deploy_job_id: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(String(512))
    # Per-operation outcome and what is needed to undo it (filled by the writer).
    results: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
