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
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
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
    # Phase 6: inspection where the doctrine wants it (IPS / file policy, SSL decryption).
    "add_inspection",
    "ssl_exempt_core",
    "ssl_decrypt_inbound",
    # The same object reachable twice (rule field / group): remove the redundant copy.
    "remove_redundant_reference",
    "remove_redundant_member",
    # A disabled rule matches nothing: removing it changes no flow (only the clutter goes).
    "remove_disabled_rule",
    # The same addresses with fewer group members: fewer ACEs, no flow changes.
    "compact_group",
)
# What a recommendation does to traffic. Behaviour-preserving changes leave every flow's verdict
# (and inspection) as it was — the batch verifier proves it before and after deployment.
# Behaviour-changing ones exist to change it (less access, more inspection, removing rules that
# saw no traffic) and are never accepted in bulk without an explicit acknowledgement.
BEHAVIOR_CHANGING = frozenset(
    {
        "remove_dead_rule",
        "tighten_source",
        "tighten_ports",
        "add_inspection",
        "ssl_decrypt_inbound",
    }
)


def behavior(kind: str) -> str:
    return "changes" if kind in BEHAVIOR_CHANGING else "preserves"


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
        Index("ix_recommendations_policy_ids", "policy_ids", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_fmc_id: Mapped[str | None] = mapped_column(String(64))
    # The access policies the item belongs to (app.analysis.policy_scope); empty: none.
    policy_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), nullable=False, default=list, server_default="{}"
    )
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
    # Executable FMC operations (app.enforce.plan): {"version", "ops", "executable", "blocked"}.
    plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


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


INSPECTION_TIERS = ("GOLD", "SILVER", "BRONZE")


class InspectionProfile(Base):
    """Which FMC intrusion / file policy implements the doctrine's inspection for a tier.

    Values are policy names as they appear in the FMC; a missing row falls back to the
    doctrine default (Cisco's built-in intrusion policies; no file policy).
    """

    __tablename__ = "inspection_profiles"
    __table_args__ = (
        CheckConstraint(
            "tier IN (" + ",".join(f"'{t}'" for t in INSPECTION_TIERS) + ")", name="tier_known"
        ),
    )

    tier: Mapped[str] = mapped_column(String(8), primary_key=True)
    ips_policy: Mapped[str | None] = mapped_column(String(256))
    file_policy: Mapped[str | None] = mapped_column(String(256))
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
