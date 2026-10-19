from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditRecord(Base):
    """Append-only, hash-chained audit trail (who / what / when / which cluster).

    Rows are never updated or deleted: the runtime DB role has no UPDATE/DELETE
    grant on this table and a trigger rejects such statements from any role.
    ``record_hash`` = HMAC(audit key, canonical record incl. ``prev_hash``).
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint("outcome IN ('success','failure','denied')", name="outcome_known"),
        Index("ix_audit_log_ts", "ts"),
        Index("ix_audit_log_action", "action"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(BigInteger)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(8), nullable=False)
    cluster: Mapped[str | None] = mapped_column(String(128))
    target: Mapped[str | None] = mapped_column(String(256))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
