"""Snapshot persistence: bulk inserts and checkpoints (synchronous SQLAlchemy).

All statements use the ORM/Core expression API with bound parameters.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.collector.signature import rule_signature
from app.fmc.records import (
    BgpRecord,
    HitCountRecord,
    InterfaceRecord,
    ObjectKind,
    ObjectRecord,
    PolicyKind,
    Ref,
    RuleRecord,
    StaticRouteRecord,
)
from app.fmc.showroute import RuntimeRoute
from app.models.inventory import (
    Bgp,
    Cluster,
    ClusterPolicy,
    FwObject,
    GroupMember,
    Interface,
    Policy,
    Route,
    Rule,
    RuleRef,
    Snapshot,
    SnapshotCheckpoint,
)

# ------------------------------------------------------------------ checkpoints


def checkpoint(session: Session, snapshot_id: int, resource: str) -> SnapshotCheckpoint:
    cp = session.get(SnapshotCheckpoint, (snapshot_id, resource))
    if cp is None:
        cp = SnapshotCheckpoint(
            snapshot_id=snapshot_id, resource=resource, next_offset=0, done=False
        )
        session.add(cp)
        session.flush()
    return cp


def advance(
    session: Session, snapshot_id: int, resource: str, next_offset: int, done: bool = False
) -> None:
    cp = checkpoint(session, snapshot_id, resource)
    cp.next_offset = next_offset
    cp.done = done
    session.execute(
        update(Snapshot).where(Snapshot.id == snapshot_id).values(heartbeat_at=datetime.now(UTC))
    )


def reset_checkpoints(session: Session, snapshot_id: int, prefix: str) -> None:
    """Forget every checkpoint whose key starts with ``prefix``."""
    session.execute(
        delete(SnapshotCheckpoint).where(
            SnapshotCheckpoint.snapshot_id == snapshot_id,
            SnapshotCheckpoint.resource.startswith(prefix, autoescape=True),
        )
    )


# ------------------------------------------------------------------ objects


def _member_row(snapshot_id: int, group_id: str, ref: Ref) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot_id,
        "group_fmc_id": group_id,
        "member_fmc_id": ref.object_id,
        "member_name": ref.name[:256],
        "member_type": ref.fmc_type[:64],
        "literal": ref.literal,
        "literal_kind": ref.literal_kind,
    }


def store_objects(session: Session, snapshot_id: int, records: Sequence[ObjectRecord]) -> int:
    if not records:
        return 0
    rows = [
        {
            "snapshot_id": snapshot_id,
            "fmc_id": r.fmc_id,
            "kind": r.kind.value,
            "fmc_type": r.fmc_type,
            "name": r.name,
            "value": r.value,
            "stub": False,
            "attrs": r.attrs,
        }
        for r in records
    ]
    session.execute(
        pg_insert(FwObject).on_conflict_do_nothing(constraint="uq_objects_snapshot_fmc"), rows
    )
    members = [_member_row(snapshot_id, r.fmc_id, m) for r in records for m in r.members]
    if members:
        session.execute(insert(GroupMember), members)
    return len(rows)


def add_stub_objects(
    session: Session, snapshot_id: int, kind_of: Callable[[str], ObjectKind]
) -> int:
    """Create stub objects for every referenced id that was not collected in full."""
    known = select(FwObject.fmc_id).where(FwObject.snapshot_id == snapshot_id)
    candidates: dict[str, tuple[str, str]] = {}
    for oid, name, typ in session.execute(
        select(RuleRef.object_fmc_id, RuleRef.object_name, RuleRef.object_type)
        .where(
            RuleRef.snapshot_id == snapshot_id,
            RuleRef.object_fmc_id.is_not(None),
            RuleRef.object_fmc_id.not_in(known),
        )
        .distinct()
    ):
        if oid:
            candidates.setdefault(oid, (name, typ))
    for oid, name, typ in session.execute(
        select(GroupMember.member_fmc_id, GroupMember.member_name, GroupMember.member_type)
        .where(
            GroupMember.snapshot_id == snapshot_id,
            GroupMember.member_fmc_id.is_not(None),
            GroupMember.member_fmc_id.not_in(known),
        )
        .distinct()
    ):
        if oid:
            candidates.setdefault(oid, (name, typ))
    rows: list[dict[str, Any]] = [
        {
            "snapshot_id": snapshot_id,
            "fmc_id": oid,
            "kind": kind_of(typ).value if typ else ObjectKind.OTHER.value,
            "fmc_type": typ,
            "name": name,
            "value": None,
            "stub": True,
            "attrs": {},
        }
        for oid, (name, typ) in candidates.items()
    ]
    if rows:
        session.execute(
            pg_insert(FwObject).on_conflict_do_nothing(constraint="uq_objects_snapshot_fmc"), rows
        )
    return len(rows)


# ------------------------------------------------------------------ rules


def store_rules(
    session: Session,
    snapshot_id: int,
    policy_id: str,
    records: Sequence[RuleRecord],
    kind: PolicyKind = PolicyKind.ACCESS,
) -> int:
    if not records:
        return 0
    rows = [
        {
            "snapshot_id": snapshot_id,
            "policy_fmc_id": policy_id,
            "policy_kind": kind.value,
            "rule_type": r.rule_type,
            "fmc_id": r.fmc_id,
            "rule_index": r.rule_index,
            "modified_at": (
                datetime.fromisoformat(str(r.attrs["modified_at"]))
                if r.attrs.get("modified_at")
                else None
            ),
            "section": r.section,
            "category": r.category,
            "name": r.name,
            "enabled": r.enabled,
            "action": r.action,
            "ips_policy": r.ips_policy,
            "ips_policy_id": r.ips_policy_id,
            "file_policy": r.file_policy,
            "file_policy_id": r.file_policy_id,
            "variable_set": r.variable_set,
            "log_begin": r.log_begin,
            "log_end": r.log_end,
            "send_events": r.send_events,
            "signature": rule_signature(r.action, r.refs),
            "attrs": r.attrs,
        }
        for r in records
    ]
    ids = dict(
        session.execute(
            insert(Rule).returning(Rule.fmc_id, Rule.id, sort_by_parameter_order=True), rows
        ).all()
    )
    refs = [
        {
            "snapshot_id": snapshot_id,
            "rule_id": ids[r.fmc_id],
            "field": field.value,
            "object_fmc_id": ref.object_id,
            "object_name": ref.name[:256],
            "object_type": ref.fmc_type[:64],
            "literal": ref.literal,
            "literal_kind": ref.literal_kind,
        }
        for r in records
        for field, ref in r.refs
    ]
    if refs:
        session.execute(insert(RuleRef), refs)
    return len(rows)


def count_rules(
    session: Session, snapshot_id: int, policy_id: str, rule_type: str | None = None
) -> int:
    """Rules stored for a policy (optionally only one rule type, e.g. AUTO NAT)."""
    query = select(func.count(Rule.id)).where(
        Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id == policy_id
    )
    if rule_type is not None:
        query = query.where(Rule.rule_type == rule_type)
    return session.scalar(query) or 0


def delete_policy_rules(session: Session, snapshot_id: int, policy_id: str) -> None:
    session.execute(
        delete(Rule).where(Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id == policy_id)
    )


def apply_hitcounts(
    session: Session, snapshot_id: int, policy_id: str, hits: Iterable[HitCountRecord]
) -> None:
    """Add hit counts per rule (summed across the units of an HA pair)."""
    for h in hits:
        rule_id, count = h.rule_id, h.hit_count
        last = datetime.fromisoformat(h.last_hit) if h.last_hit else None
        values: dict[str, Any] = {"hit_count": func.coalesce(Rule.hit_count, 0) + count}
        if last is not None:
            values["last_hit"] = func.greatest(func.coalesce(Rule.last_hit, last), last)
        if h.deploy_known:
            deployed = datetime.fromisoformat(h.deployed_at) if h.deployed_at else None
            if deployed is None:
                values["never_deployed"] = True
            else:
                values["deployed_at"] = func.greatest(
                    func.coalesce(Rule.deployed_at, deployed), deployed
                )
        session.execute(
            update(Rule)
            .where(
                Rule.snapshot_id == snapshot_id,
                Rule.policy_fmc_id == policy_id,
                Rule.fmc_id == rule_id,
            )
            .values(**values)
        )


# ------------------------------------------------------------------ topology


def replace_clusters(session: Session, snapshot_id: int, rows: list[dict[str, Any]]) -> None:
    session.execute(delete(Cluster).where(Cluster.snapshot_id == snapshot_id))
    if rows:
        session.execute(insert(Cluster), [{"snapshot_id": snapshot_id, **r} for r in rows])


def upsert_policy(session: Session, snapshot_id: int, row: dict[str, Any]) -> None:
    stmt = pg_insert(Policy).values(snapshot_id=snapshot_id, **row)
    session.execute(
        stmt.on_conflict_do_update(
            constraint="uq_policies_snapshot_fmc",
            set_={
                "kind": stmt.excluded.kind,
                "name": stmt.excluded.name,
                "default_action": stmt.excluded.default_action,
                "categories": stmt.excluded.categories,
                "links": stmt.excluded.links,
                "attrs": stmt.excluded.attrs,
            },
        )
    )


def replace_cluster_policies(
    session: Session, snapshot_id: int, rows: list[dict[str, str]]
) -> None:
    session.execute(delete(ClusterPolicy).where(ClusterPolicy.snapshot_id == snapshot_id))
    if rows:
        session.execute(insert(ClusterPolicy), [{"snapshot_id": snapshot_id, **r} for r in rows])


def replace_interfaces(
    session: Session,
    snapshot_id: int,
    cluster_id: str,
    device_id: str,
    kind: str,
    records: Sequence[InterfaceRecord],
) -> None:
    session.execute(
        delete(Interface).where(
            Interface.snapshot_id == snapshot_id,
            Interface.cluster_fmc_id == cluster_id,
            Interface.kind == kind,
        )
    )
    if records:
        session.execute(
            insert(Interface),
            [
                {
                    "snapshot_id": snapshot_id,
                    "cluster_fmc_id": cluster_id,
                    "device_fmc_id": device_id,
                    "fmc_id": r.fmc_id,
                    "kind": r.kind,
                    "name": r.name,
                    "ifname": r.ifname,
                    "enabled": r.enabled,
                    "zone_fmc_id": r.zone_id,
                    "ipv4": r.ipv4,
                    "vlan": r.vlan,
                }
                for r in records
            ],
        )


def replace_static_routes(
    session: Session, snapshot_id: int, cluster_id: str, records: Sequence[StaticRouteRecord]
) -> None:
    session.execute(
        delete(Route).where(
            Route.snapshot_id == snapshot_id,
            Route.cluster_fmc_id == cluster_id,
            Route.kind == "static",
        )
    )
    ids = {n.object_id for r in records for n in r.networks if n.object_id}
    ids |= {r.gateway.object_id for r in records if r.gateway and r.gateway.object_id}
    values = (
        dict(
            session.execute(
                select(FwObject.fmc_id, FwObject.value).where(
                    FwObject.snapshot_id == snapshot_id, FwObject.fmc_id.in_(ids)
                )
            ).all()
        )
        if ids
        else {}
    )
    rows: list[dict[str, Any]] = []
    for r in records:
        gateway, gateway_id, literal = None, None, False
        if r.gateway is not None:
            if r.gateway.object_id:
                gateway_id = r.gateway.object_id
                gateway = _strip_host(values.get(gateway_id))
            else:
                gateway, literal = _strip_host(r.gateway.literal), True
        for net in r.networks or (Ref(),):
            rows.append(
                {
                    "snapshot_id": snapshot_id,
                    "cluster_fmc_id": cluster_id,
                    "kind": "static",
                    "fmc_id": r.fmc_id,
                    "interface": r.interface,
                    "network_fmc_id": net.object_id,
                    "network_name": net.name,
                    "network": values.get(net.object_id or ""),
                    "gateway": gateway,
                    "gateway_fmc_id": gateway_id,
                    "gateway_is_literal": literal,
                    "metric": r.metric,
                }
            )
    if rows:
        session.execute(insert(Route), rows)


def _strip_host(value: str | None) -> str | None:
    if value is None:
        return None
    return value.removesuffix("/32").removesuffix("/128")


def replace_connected_routes(session: Session, snapshot_id: int, cluster_id: str) -> None:
    session.execute(
        delete(Route).where(
            Route.snapshot_id == snapshot_id,
            Route.cluster_fmc_id == cluster_id,
            Route.kind == "connected",
        )
    )
    rows: list[dict[str, Any]] = []
    for ifname, cidr in session.execute(
        select(Interface.ifname, Interface.ipv4).where(
            Interface.snapshot_id == snapshot_id,
            Interface.cluster_fmc_id == cluster_id,
            Interface.ipv4.is_not(None),
        )
    ):
        rows.append(
            {
                "snapshot_id": snapshot_id,
                "cluster_fmc_id": cluster_id,
                "kind": "connected",
                "interface": ifname,
                "network": str(ipaddress.ip_interface(cidr or "").network),
                "metric": 0,
                "gateway_is_literal": False,
            }
        )
    if rows:
        session.execute(insert(Route), rows)


def replace_dynamic_routes(
    session: Session, snapshot_id: int, cluster_id: str, routes: Sequence[RuntimeRoute]
) -> int:
    """Routes learned by routing protocols (connected, local and static come from config)."""
    session.execute(
        delete(Route).where(
            Route.snapshot_id == snapshot_id,
            Route.cluster_fmc_id == cluster_id,
            Route.kind == "dynamic",
        )
    )
    rows = [
        {
            "snapshot_id": snapshot_id,
            "cluster_fmc_id": cluster_id,
            "kind": "dynamic",
            "interface": r.interface,
            "network": r.network,
            "network_name": "",
            "gateway": r.gateway,
            "gateway_is_literal": True,
            "metric": min(r.metric or 0, 2**31 - 1),
            "protocol": f"{r.protocol} {r.subtype}".strip(),
            "distance": r.distance,
        }
        for r in routes
        if r.protocol not in ("connected", "local", "static")
    ]
    if rows:
        session.execute(insert(Route), rows)
    return len(rows)


def replace_bgp(
    session: Session, snapshot_id: int, cluster_id: str, record: BgpRecord | None
) -> None:
    session.execute(
        delete(Bgp).where(Bgp.snapshot_id == snapshot_id, Bgp.cluster_fmc_id == cluster_id)
    )
    if record is not None:
        session.add(
            Bgp(
                snapshot_id=snapshot_id,
                cluster_fmc_id=cluster_id,
                as_number=record.as_number,
                router_id=record.router_id,
                neighbors=list(record.neighbors),
            )
        )
