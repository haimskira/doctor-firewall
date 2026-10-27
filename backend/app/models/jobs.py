"""Background job runs: what was queued, by whom, and how far the worker has got."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

JOB_KINDS = ("collect", "analyze", "batch", "rollback", "audit_verify")
JOB_STATUSES = ("queued", "running", "done", "failed")


def _in(values: tuple[str, ...]) -> str:
    return ",".join(f"'{v}'" for v in values)


class JobRun(Base):
    __tablename__ = "job_runs"
    __table_args__ = (
        CheckConstraint(f"kind IN ({_in(JOB_KINDS)})", name="kind_known"),
        CheckConstraint(f"status IN ({_in(JOB_STATUSES)})", name="status_known"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="progress_range"),
        Index("ix_job_runs_status", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # What the job works on: a snapshot (collect / analyze) or a batch (batch / rollback).
    snapshot_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    batch_id: Mapped[int | None] = mapped_column(BigInteger)
    changeset_id: Mapped[int | None] = mapped_column(BigInteger)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # The step the worker is in, as a message key plus its parameters (e.g. policy 3 of 5).
    step: Mapped[str] = mapped_column(String(64), nullable=False, default="queued")
    step_args: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(String(512))
    rq_job_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
