from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FmcConnection(Base):
    """Connection details for the FMC (single FMC in HA, reached through its VIP).

    The API password is stored only as an AES-GCM token (see :class:`app.core.crypto.SecretBox`)
    bound to the context returned by :meth:`password_context`.
    """

    __tablename__ = "fmc_connections"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="port_range"),
        CheckConstraint(
            "sync_interval_minutes IS NULL OR sync_interval_minutes BETWEEN 15 AND 10080",
            name="sync_interval_range",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    password_enc: Mapped[str] = mapped_column(Text, nullable=False)
    # Discovered from the generatetoken response; kept as a parameter for every call.
    # PEM of the one FMC certificate this connection trusts (pinning, confirmed by an admin);
    # NULL = verify against the CA bundle and the host name.
    pinned_cert: Mapped[str | None] = mapped_column(Text)
    domain_uuid: Mapped[str | None] = mapped_column(String(36))
    server_version: Mapped[str | None] = mapped_column(String(128))
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_ok: Mapped[bool | None] = mapped_column()
    # Periodic read-only collection; NULL disables automatic sync.
    sync_interval_minutes: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    @staticmethod
    def password_context(connection_id: int) -> str:
        return f"fmc_connection:{connection_id}:password"


class FmcEvent(Base):
    """The FMC integration log (app.fmc.trace): one row per request or operation event.

    Never holds credentials, tokens or request bodies; ``response`` is the scrubbed, truncated
    body of a failed request only. Pruned after 30 days.
    """

    __tablename__ = "fmc_events"
    __table_args__ = (
        CheckConstraint(
            "operation IN ('test','collect','batch','revert','rollback','watch')",
            name="operation_known",
        ),
        CheckConstraint("kind IN ('started','request','failed','finished')", name="kind_known"),
        CheckConstraint("outcome IN ('ok','error')", name="outcome_known"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    op_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # one operation
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    connection_id: Mapped[int | None] = mapped_column(Integer, index=True)
    connection_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    snapshot_id: Mapped[int | None] = mapped_column(Integer, index=True)
    batch_id: Mapped[int | None] = mapped_column(Integer, index=True)
    run_id: Mapped[int | None] = mapped_column(Integer, index=True)
    step: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str] = mapped_column(String(8), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False, default="")
    path: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    status: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    response: Mapped[str] = mapped_column(Text, nullable=False, default="")
