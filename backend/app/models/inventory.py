"""Snapshot storage: the local copy of the FMC configuration.

Every collection is a separate, timestamped snapshot; nothing is overwritten, so
snapshots can be compared to detect drift. Objects are stored once per snapshot and
referenced by FMC id from rules and groups (the object graph). ACE expansion is never
stored — it is derived from the graph during analysis.
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
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SNAPSHOT_STATUSES = ("pending", "running", "complete", "failed")


def _snapshot_fk() -> Mapped[int]:
    return mapped_column(BigInteger, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False)


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (
        CheckConstraint("status IN ('pending','running','complete','failed')", name="status_known"),
        Index("ix_snapshots_connection_created", "connection_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    connection_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("fmc_connections.id", ondelete="SET NULL")
    )
    connection_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fmc_version: Mapped[str | None] = mapped_column(String(128))
    domain_uuid: Mapped[str | None] = mapped_column(String(36))
    error: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(String(512))
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SnapshotCheckpoint(Base):
    """Progress per collected resource, so a failed collection resumes where it stopped."""

    __tablename__ = "snapshot_checkpoints"

    snapshot_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("snapshots.id", ondelete="CASCADE"), primary_key=True
    )
    resource: Mapped[str] = mapped_column(String(256), primary_key=True)
    next_offset: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    done: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class Cluster(Base):
    """An enforcement unit: FTD HA pair, FTD cluster, or standalone device."""

    __tablename__ = "clusters"
    __table_args__ = (UniqueConstraint("snapshot_id", "fmc_id", name="uq_clusters_snapshot_fmc"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # ha_pair | standalone
    policy_fmc_id: Mapped[str | None] = mapped_column(String(64))
    primary_device_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sw_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    members: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("snapshot_id", "fmc_id", name="uq_policies_snapshot_fmc"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    default_action: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "policy_fmc_id", "fmc_id", name="uq_rules_identity"),
        Index("ix_rules_order", "snapshot_id", "policy_fmc_id", "rule_index"),
        Index("ix_rules_signature", "snapshot_id", "policy_fmc_id", "signature"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    policy_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_index: Mapped[int] = mapped_column(Integer, nullable=False)
    section: Mapped[str] = mapped_column(String(32), nullable=False)
    category: Mapped[str] = mapped_column(String(256), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    ips_policy: Mapped[str | None] = mapped_column(String(256))
    file_policy: Mapped[str | None] = mapped_column(String(256))
    variable_set: Mapped[str | None] = mapped_column(String(256))
    log_begin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    log_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    send_events: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hit_count: Mapped[int | None] = mapped_column(BigInteger)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    attrs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class FwObject(Base):
    __tablename__ = "objects"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "fmc_id", name="uq_objects_snapshot_fmc"),
        Index("ix_objects_kind_value", "snapshot_id", "kind", "value"),
        Index("ix_objects_name", "snapshot_id", "name"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    fmc_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    value: Mapped[str | None] = mapped_column(Text)
    # True when known only from a reference (e.g. applications), not fetched in full.
    stub: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attrs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class GroupMember(Base):
    __tablename__ = "group_members"
    __table_args__ = (
        CheckConstraint("(member_fmc_id IS NULL) <> (literal IS NULL)", name="member_xor_literal"),
        Index("ix_group_members_group", "snapshot_id", "group_fmc_id"),
        Index("ix_group_members_member", "snapshot_id", "member_fmc_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    group_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    member_fmc_id: Mapped[str | None] = mapped_column(String(64))
    member_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    member_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    literal: Mapped[str | None] = mapped_column(Text)
    literal_kind: Mapped[str | None] = mapped_column(String(16))


class RuleRef(Base):
    __tablename__ = "rule_refs"
    __table_args__ = (
        CheckConstraint("(object_fmc_id IS NULL) <> (literal IS NULL)", name="object_xor_literal"),
        Index("ix_rule_refs_rule", "rule_id"),
        Index("ix_rule_refs_object", "snapshot_id", "object_fmc_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    rule_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("rules.id", ondelete="CASCADE"), nullable=False
    )
    field: Mapped[str] = mapped_column(String(16), nullable=False)
    object_fmc_id: Mapped[str | None] = mapped_column(String(64))
    object_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    object_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    literal: Mapped[str | None] = mapped_column(Text)
    literal_kind: Mapped[str | None] = mapped_column(String(16))


class Interface(Base):
    __tablename__ = "interfaces"
    __table_args__ = (Index("ix_interfaces_cluster", "snapshot_id", "cluster_fmc_id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    cluster_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    ifname: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    zone_fmc_id: Mapped[str | None] = mapped_column(String(64))
    ipv4: Mapped[str | None] = mapped_column(String(64))
    vlan: Mapped[int | None] = mapped_column(Integer)


class Route(Base):
    __tablename__ = "routes"
    __table_args__ = (
        CheckConstraint("kind IN ('static','connected')", name="kind_known"),
        Index("ix_routes_cluster", "snapshot_id", "cluster_fmc_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    cluster_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    fmc_id: Mapped[str | None] = mapped_column(String(64))
    interface: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    network_fmc_id: Mapped[str | None] = mapped_column(String(64))
    network_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    network: Mapped[str | None] = mapped_column(String(64))
    gateway: Mapped[str | None] = mapped_column(String(64))
    gateway_fmc_id: Mapped[str | None] = mapped_column(String(64))
    gateway_is_literal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metric: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Bgp(Base):
    __tablename__ = "bgp"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    cluster_fmc_id: Mapped[str] = mapped_column(String(64), nullable=False)
    as_number: Mapped[str | None] = mapped_column(String(32))
    router_id: Mapped[str | None] = mapped_column(String(64))
    neighbors: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False, default=list)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("severity IN ('info','low','medium','high')", name="severity_known"),
        Index("ix_findings_snapshot_kind", "snapshot_id", "kind"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = _snapshot_fk()
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    policy_fmc_id: Mapped[str | None] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
