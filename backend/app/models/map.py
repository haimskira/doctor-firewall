"""Phase 4: connectivity map edges (derived per snapshot by the analysis job)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MapEdge(Base):
    """Source node -> destination node through the rules of one policy."""

    __tablename__ = "map_edges"
    __table_args__ = (
        CheckConstraint("risk IN ('green','yellow','red')", name="risk_known"),
        Index("ix_map_edges_snapshot", "snapshot_id", "policy_fmc_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    policy_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    src_node: Mapped[str] = mapped_column(String(200), nullable=False)
    dst_node: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False)
    hits: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    min_score: Mapped[int | None] = mapped_column(Integer)
    risk: Mapped[str] = mapped_column(String(8), nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    services: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
