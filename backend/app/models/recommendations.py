"""Phase 3: recommendations, operator decisions and the naming convention.

Recommendations are derived per snapshot by the analysis job (never edited by hand).
Decisions are keyed by a stable fingerprint so that an accepted or dismissed
recommendation stays decided when the next pull produces the same proposal. Nothing
here writes to the FMC: accepted recommendations are the input of the (phase 5)
changeset and deploy flow.
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
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

RECOMMENDATION_KINDS = (
    "remove_shadowed_rule",
    "remove_dead_rule",
    "remove_unused_object",
    "merge_duplicate_objects",
    "merge_groups",
    "split_group",
    "split_rule",
    "merge_rules",
    "tighten_source",
    "tighten_ports",
    "rename_role",
    "rename_convention",
    "literal_to_object",
)
DECISIONS = ("accepted", "dismissed")
# Object kinds a naming convention can be defined for ("rule" = access rules).
CONVENTION_KINDS = (
    "host",
    "network",
    "range",
    "fqdn",
    "network_group",
    "port",
    "port_group",
    "rule",
)


class Recommendation(Base):
    __tablename__ = "recommendations"
    __table_args__ = (
        CheckConstraint(
            "kind IN (" + ",".join(f"'{k}'" for k in RECOMMENDATION_KINDS) + ")",
            name="kind_known",
        ),
        CheckConstraint("display IN ('inline','split')", name="display_known"),
        CheckConstraint("deploy_cost >= 0", name="deploy_cost_positive"),
        Index("ix_recommendations_snapshot_kind", "snapshot_id", "kind"),
        Index("ix_recommendations_snapshot_priority", "snapshot_id", "priority"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_fmc_id: Mapped[str | None] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    # Doctrine principle the recommendation serves (an i18n key on the client).
    principle: Mapped[str] = mapped_column(String(48), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100, higher first
    # [{"type": "rule"|"object", "id": ..., "name": ...}] — what the change touches.
    targets: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    # Structured before/after (see app.analysis.recommend for the shape).
    preview: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    display: Mapped[str] = mapped_column(String(8), nullable=False)
    deploy_cost: Mapped[int] = mapped_column(Integer, nullable=False)
    ace_delta: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    score_delta: Mapped[int | None] = mapped_column(Integer)
    warnings: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class RecommendationDecision(Base):
    """An operator's decision on a recommendation, valid across snapshots."""

    __tablename__ = "recommendation_decisions"
    __table_args__ = (CheckConstraint("status IN ('accepted','dismissed')", name="status_known"),)

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    note: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    decided_by: Mapped[str] = mapped_column(String(64), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class NamingConvention(Base):
    """Admin-defined name template per object kind (and for rules)."""

    __tablename__ = "naming_conventions"
    __table_args__ = (
        CheckConstraint(
            "kind IN (" + ",".join(f"'{k}'" for k in CONVENTION_KINDS) + ")", name="kind_known"
        ),
        CheckConstraint("letter_case IN ('upper','lower','keep')", name="case_known"),
    )

    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    template: Mapped[str] = mapped_column(String(128), nullable=False)
    letter_case: Mapped[str] = mapped_column(String(8), nullable=False, default="upper")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
