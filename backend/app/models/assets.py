"""Asset table (doctrine classification) and per-cluster platform limits.

These are operator-maintained and not tied to a snapshot: they survive every pull.
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
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Server tiers per the doctrine, CORE (shared infrastructure) and USERS (user space,
# outside the tiers; the user_type column says which population).
TIERS = ("CORE", "GOLD", "SILVER", "BRONZE", "USERS")


ASSET_KINDS = ("system", "server", "user", "user_segment")


class AssetGroup(Base):
    """An asset: a whole system, a single server, a single user or a user segment.

    It owns its classification (tier, user type); its components (``Asset`` rows) carry the
    addresses, ports and roles. For the analysis a component inside an asset *is* that asset:
    it takes the asset's name and tier (see :func:`app.analysis.assets.effective_assets`).
    """

    __tablename__ = "asset_groups"
    __table_args__ = (
        CheckConstraint("tier IN ('CORE','GOLD','SILVER','BRONZE','USERS')", name="tier_known"),
        CheckConstraint("kind IN ('system','server','user','user_segment')", name="kind_known"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="system")
    tier: Mapped[str] = mapped_column(String(8), nullable=False)
    user_type: Mapped[str | None] = mapped_column(String(16))
    owner: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class Asset(Base):
    """An address block classified against the doctrine (the ground truth for analysis).

    Inside an asset (``group_id``) it is one of the asset's components (``system`` = the
    component's name, ``system_type`` = its role); on its own it is a stand-alone entry
    (legacy rows and bootstrap suggestions waiting to be assigned).
    """

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("tier IN ('CORE','GOLD','SILVER','BRONZE','USERS')", name="tier_known"),
        CheckConstraint("source IN ('manual','csv','bootstrap')", name="source_known"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), index=True
    )
    # Canonical CIDR ("10.20.5.0/24", hosts as /32) or range ("a-b").
    network: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    system: Mapped[str] = mapped_column(String(128), nullable=False)
    tier: Mapped[str] = mapped_column(String(8), nullable=False)
    system_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    user_type: Mapped[str | None] = mapped_column(String(16))
    ports: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    notes: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    # Bootstrap suggestions stay unconfirmed until an operator accepts them; only
    # confirmed assets feed the analysis.
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class ClusterSetting(Base):
    """Per-cluster platform limits. Defaults are explicitly marked unverified."""

    __tablename__ = "cluster_settings"
    __table_args__ = (
        CheckConstraint("ace_limit > 0", name="ace_limit_positive"),
        CheckConstraint("deploy_change_limit > 0", name="deploy_limit_positive"),
    )

    cluster_fmc_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ace_limit: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ace_limit_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deploy_change_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    deploy_limit_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class RuleScore(Base):
    """Phase-2 analysis result per rule (recomputed on every analysis run)."""

    __tablename__ = "rule_scores"

    rule_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True
    )
    snapshot_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[int | None] = mapped_column(Integer)  # None: not scored (deny, disabled...)
    ace_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    src_tiers: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    dst_tiers: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    shadowed_by: Mapped[str | None] = mapped_column(String(64))
    dead: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
