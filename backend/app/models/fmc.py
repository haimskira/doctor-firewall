from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String, Text, func
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
