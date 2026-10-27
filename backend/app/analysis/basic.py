"""Phase-1 analysis of a snapshot: the first view of "the mess".

Findings are read-only observations with a severity; nothing here changes anything.

* duplicate_object     - same type and canonical value under different names
* identical_rules      - rules in one policy with the same match + action
* deep_nesting         - group nesting deeper than DEPTH_LIMIT (ACE blow-up source)
* group_cycle          - groups that (transitively) contain themselves
* duplicate_membership - an object reaching a group / rule field through several paths
* inline_literal       - raw values used where a named object should be (orphans)
* unused_object        - objects referenced by nothing in the collected scope
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, exists, func, insert, or_, select, update
from sqlalchemy.orm import Session

from app.analysis.graph import (
    GroupGraph,
    Leaf,
    combine,
    depths,
    introduced_duplicates,
    leaf_counts,
    strongly_connected,
)
from app.fmc.records import GROUP_KINDS, ObjectKind
from app.models.inventory import (
    Cluster,
    Finding,
    FwObject,
    GroupMember,
    Interface,
    Policy,
    Route,
    Rule,
    RuleRef,
    Snapshot,
)

DEPTH_LIMIT = 3
MAX_LISTED = 50
VALUE_KINDS = (
    ObjectKind.HOST,
    ObjectKind.NETWORK,
    ObjectKind.RANGE,
    ObjectKind.FQDN,
    ObjectKind.PORT,
    ObjectKind.ICMP,
    ObjectKind.SGT,
    ObjectKind.URL,
)


@dataclass
class FindingRow:
    kind: str
    severity: str
    title: str
    policy_fmc_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


def _names(session: Session, snapshot_id: int) -> dict[str, tuple[str, str]]:
    return {
        fid: (name, kind)
        for fid, name, kind in session.execute(
            select(FwObject.fmc_id, FwObject.name, FwObject.kind).where(
                FwObject.snapshot_id == snapshot_id
            )
        )
    }


def duplicate_objects(session: Session, snapshot_id: int) -> list[FindingRow]:
    rows = session.execute(
        select(
            FwObject.kind,
            FwObject.value,
            func.array_agg(FwObject.fmc_id),
            func.array_agg(FwObject.name),
        )
        .where(
            FwObject.snapshot_id == snapshot_id,
            FwObject.stub.is_(False),
            FwObject.value.is_not(None),
            FwObject.kind.in_([k.value for k in VALUE_KINDS]),
        )
        .group_by(FwObject.kind, FwObject.value)
        .having(func.count() > 1)
    )
    return [
        FindingRow(
            kind="duplicate_object",
            severity="low",
            title=f"{len(ids)} {kind} objects with value {value}",
            details={
                "value": value,
                "objects": [
                    {"id": i, "name": n}
                    for i, n in sorted(zip(ids, names, strict=True), key=lambda x: x[1])
                ],
            },
        )
        for kind, value, ids, names in rows
    ]


def identical_rules(session: Session, snapshot_id: int) -> list[FindingRow]:
    rows = session.execute(
        select(
            Rule.policy_fmc_id,
            Rule.signature,
            func.array_agg(
                func.json_build_object(
                    "id",
                    Rule.fmc_id,
                    "name",
                    Rule.name,
                    "index",
                    Rule.rule_index,
                    "enabled",
                    Rule.enabled,
                )
            ),
        )
        .where(Rule.snapshot_id == snapshot_id)
        .group_by(Rule.policy_fmc_id, Rule.signature)
        .having(func.count() > 1)
    )
    findings = []
    for policy, _sig, rules in rows:
        ordered = sorted(rules, key=lambda r: r["index"])
        findings.append(
            FindingRow(
                kind="identical_rules",
                severity="medium",
                policy_fmc_id=policy,
                title=f"{len(ordered)} identical rules: "
                + ", ".join(f"#{r['index']} {r['name']}" for r in ordered[:5]),
                details={"rules": ordered[:MAX_LISTED]},
            )
        )
    return findings


def load_graph(session: Session, snapshot_id: int) -> GroupGraph:
    graph = GroupGraph()
    group_ids = set(
        session.scalars(
            select(FwObject.fmc_id).where(
                FwObject.snapshot_id == snapshot_id,
                FwObject.kind.in_([k.value for k in GROUP_KINDS]),
            )
        )
    )
    for gid in group_ids:
        graph.members[gid] = []
    for group, member, literal in session.execute(
        select(GroupMember.group_fmc_id, GroupMember.member_fmc_id, GroupMember.literal)
        .where(GroupMember.snapshot_id == snapshot_id)
        .order_by(GroupMember.id)
    ):
        graph.members.setdefault(group, []).append(member or f"lit:{literal}")
    return graph


def _leaf_label(leaf: Leaf, names: dict[str, tuple[str, str]]) -> dict[str, str]:
    if leaf.startswith("lit:"):
        return {"literal": leaf[4:]}
    return {"id": leaf, "name": names.get(leaf, ("?", ""))[0]}


def group_findings(
    graph: GroupGraph, names: dict[str, tuple[str, str]], rule_referenced: set[str]
) -> tuple[list[FindingRow], set[str], dict[str, Counter[Leaf]]]:
    findings: list[FindingRow] = []
    cycles = strongly_connected(graph)
    cyclic = {g for cycle in cycles for g in cycle}
    for cycle in cycles:
        findings.append(
            FindingRow(
                kind="group_cycle",
                severity="high",
                title="Group cycle: " + " -> ".join(names.get(g, (g, ""))[0] for g in cycle),
                details={"groups": [{"id": g, "name": names.get(g, ("?", ""))[0]} for g in cycle]},
            )
        )
    depth = depths(graph, cyclic)
    parents: dict[str, set[str]] = defaultdict(set)
    for group, members in graph.members.items():
        for m in members:
            if graph.is_group(m):
                parents[m].add(group)
    for group, d in depth.items():
        top_level = not parents[group] or group in rule_referenced
        if d > DEPTH_LIMIT and top_level:
            findings.append(
                FindingRow(
                    kind="deep_nesting",
                    severity="medium",
                    title=f"{names.get(group, (group, ''))[0]}: nesting depth {d} "
                    f"(limit {DEPTH_LIMIT})",
                    details={
                        "group": {"id": group, "name": names.get(group, ("?", ""))[0]},
                        "depth": d,
                    },
                )
            )
    counts = leaf_counts(graph, cyclic)
    for group, total in counts.items():
        parts = [counts[c] for c in graph.child_groups(group) if c in counts]
        dups = introduced_duplicates(total, parts)
        if dups:
            findings.append(
                FindingRow(
                    kind="duplicate_membership",
                    severity="low",
                    title=f"{names.get(group, (group, ''))[0]}: {len(dups)} member(s) reachable "
                    "through more than one path",
                    details={
                        "group": {"id": group, "name": names.get(group, ("?", ""))[0]},
                        "members": [
                            {**_leaf_label(leaf, names), "paths": n}
                            for leaf, n in list(dups.items())[:MAX_LISTED]
                        ],
                    },
                )
            )
    return findings, cyclic, counts


def rule_membership_findings(
    session: Session,
    snapshot_id: int,
    graph: GroupGraph,
    counts: dict[str, Counter[Leaf]],
    names: dict[str, tuple[str, str]],
) -> list[FindingRow]:
    findings: list[FindingRow] = []
    rows = session.execute(
        select(
            Rule.id,
            Rule.policy_fmc_id,
            Rule.fmc_id,
            Rule.name,
            Rule.rule_index,
            RuleRef.field,
            RuleRef.object_fmc_id,
            RuleRef.literal,
        )
        .join(RuleRef, RuleRef.rule_id == Rule.id)
        .where(Rule.snapshot_id == snapshot_id)
        .order_by(Rule.id)
    )
    current: int | None = None
    meta: tuple[str, str, str, int] = ("", "", "", 0)
    fields: dict[str, list[str]] = defaultdict(list)

    def flush() -> None:
        problems = []
        for fld, refs in fields.items():
            total, parts = combine(refs, graph, counts)
            dups = introduced_duplicates(total, parts)
            if dups:
                problems.append(
                    {
                        "field": fld,
                        "members": [
                            {**_leaf_label(leaf, names), "paths": n}
                            for leaf, n in list(dups.items())[:20]
                        ],
                    }
                )
        if problems:
            policy, rule_id, name, index = meta
            findings.append(
                FindingRow(
                    kind="duplicate_membership",
                    severity="low",
                    policy_fmc_id=policy,
                    title=f"Rule #{index} {name}: the same object is referenced more than once",
                    details={
                        "rule": {"id": rule_id, "name": name, "index": index},
                        "fields": problems,
                    },
                )
            )

    for rid, policy, rule_fmc_id, name, index, fld, obj, literal in rows:
        if rid != current:
            if current is not None:
                flush()
            current, meta, fields = rid, (policy, rule_fmc_id, name, index), defaultdict(list)
        fields[fld].append(obj or f"lit:{literal}")
    if current is not None:
        flush()
    return findings


def inline_literals(session: Session, snapshot_id: int) -> list[FindingRow]:
    findings: list[FindingRow] = []
    for policy, literal, kind, rules in session.execute(
        select(
            Rule.policy_fmc_id,
            RuleRef.literal,
            RuleRef.literal_kind,
            func.array_agg(
                func.json_build_object(
                    "id",
                    Rule.fmc_id,
                    "name",
                    Rule.name,
                    "index",
                    Rule.rule_index,
                    "field",
                    RuleRef.field,
                )
            ),
        )
        .join(RuleRef, RuleRef.rule_id == Rule.id)
        .where(Rule.snapshot_id == snapshot_id, RuleRef.literal.is_not(None))
        .group_by(Rule.policy_fmc_id, RuleRef.literal, RuleRef.literal_kind)
    ):
        ordered = sorted(rules, key=lambda r: r["index"])
        findings.append(
            FindingRow(
                kind="inline_literal",
                severity="low",
                policy_fmc_id=policy,
                title=f"Inline {kind} {literal} used in {len(ordered)} rule(s) without an object",
                details={
                    "literal": literal,
                    "literal_kind": kind,
                    "where": "rule",
                    "rules": ordered[:MAX_LISTED],
                },
            )
        )
    in_groups = session.execute(
        select(
            GroupMember.literal, GroupMember.literal_kind, func.array_agg(GroupMember.group_fmc_id)
        )
        .where(GroupMember.snapshot_id == snapshot_id, GroupMember.literal.is_not(None))
        .group_by(GroupMember.literal, GroupMember.literal_kind)
    ).all()
    group_ids = {g for _l, _k, groups in in_groups for g in groups}
    group_names: dict[str, str] = dict(
        session.execute(
            select(FwObject.fmc_id, FwObject.name).where(
                FwObject.snapshot_id == snapshot_id, FwObject.fmc_id.in_(group_ids)
            )
        ).all()
    )
    for literal, kind, groups in in_groups:
        findings.append(
            FindingRow(
                kind="inline_literal",
                severity="low",
                title=f"Inline {kind} {literal} inside {len(groups)} group(s) without an object",
                details={
                    "literal": literal,
                    "literal_kind": kind,
                    "where": "group",
                    "groups": [
                        {"id": g, "name": group_names.get(g, g)}
                        for g in sorted(set(groups), key=lambda g: group_names.get(g, g))
                    ][:MAX_LISTED],
                },
            )
        )
    for gateway, routes in session.execute(
        select(
            Route.gateway,
            func.array_agg(
                func.json_build_object(
                    "cluster",
                    Route.cluster_fmc_id,
                    "cluster_name",
                    Cluster.name,
                    "interface",
                    Route.interface,
                    "network",
                    Route.network_name,
                )
            ),
        )
        .outerjoin(
            Cluster,
            (Cluster.snapshot_id == Route.snapshot_id) & (Cluster.fmc_id == Route.cluster_fmc_id),
        )
        .where(Route.snapshot_id == snapshot_id, Route.gateway_is_literal.is_(True))
        .group_by(Route.gateway)
    ):
        findings.append(
            FindingRow(
                kind="inline_literal",
                severity="low",
                title=f"Static route gateway {gateway} is a raw address, not an object",
                details={
                    "literal": gateway,
                    "literal_kind": "address",
                    "where": "route",
                    "routes": routes[:MAX_LISTED],
                },
            )
        )
    return findings


def disabled_rules(session: Session, snapshot_id: int) -> list[FindingRow]:
    """Rules left disabled: they match nothing, but clutter the policy and its review."""
    rows = session.execute(
        select(Rule.policy_fmc_id, Rule.fmc_id, Rule.name, Rule.rule_index, Rule.modified_at)
        .join(
            Policy,
            (Policy.snapshot_id == Rule.snapshot_id) & (Policy.fmc_id == Rule.policy_fmc_id),
        )
        .where(
            Rule.snapshot_id == snapshot_id,
            Rule.enabled.is_(False),
            Policy.kind.in_(("access", "prefilter")),
        )
        .order_by(Rule.policy_fmc_id, Rule.rule_index)
    )
    return [
        FindingRow(
            kind="disabled_rule",
            severity="info",
            policy_fmc_id=policy,
            title=f"#{index} {name} is disabled",
            details={
                "rule": {"id": fid, "name": name, "index": index},
                "modified_at": modified.isoformat() if modified else None,
            },
        )
        for policy, fid, name, index, modified in rows
    ]


def unused_objects(session: Session, snapshot_id: int) -> list[FindingRow]:
    o = FwObject
    used_by_rule = exists().where(
        RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id == o.fmc_id
    )
    used_in_group = exists().where(
        GroupMember.snapshot_id == snapshot_id, GroupMember.member_fmc_id == o.fmc_id
    )
    used_by_route = exists().where(
        Route.snapshot_id == snapshot_id,
        or_(Route.network_fmc_id == o.fmc_id, Route.gateway_fmc_id == o.fmc_id),
    )
    used_by_iface = exists().where(
        Interface.snapshot_id == snapshot_id, Interface.zone_fmc_id == o.fmc_id
    )
    rows = session.execute(
        select(o.fmc_id, o.name, o.kind)
        .where(
            o.snapshot_id == snapshot_id,
            o.stub.is_(False),
            ~used_by_rule,
            ~used_in_group,
            ~used_by_route,
            ~used_by_iface,
        )
        .order_by(o.kind, o.name)
    )
    return [
        FindingRow(
            kind="unused_object",
            severity="info",
            title=f"{kind} {name} is not used by any collected rule, group, route or interface",
            details={"object": {"id": fid, "name": name, "kind": kind}},
        )
        for fid, name, kind in rows
    ]


def analyze(session: Session, snapshot_id: int) -> dict[str, int]:
    """Recompute all phase-1 findings for a snapshot (idempotent). Caller commits."""
    session.execute(delete(Finding).where(Finding.snapshot_id == snapshot_id))
    names = _names(session, snapshot_id)
    graph = load_graph(session, snapshot_id)
    rule_referenced = {
        oid
        for oid in session.scalars(
            select(RuleRef.object_fmc_id)
            .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id.is_not(None))
            .distinct()
        )
        if oid
    }
    findings = duplicate_objects(session, snapshot_id) + identical_rules(session, snapshot_id)
    group_rows, _cyclic, counts = group_findings(graph, names, rule_referenced)
    findings += group_rows
    findings += rule_membership_findings(session, snapshot_id, graph, counts, names)
    findings += inline_literals(session, snapshot_id)
    findings += unused_objects(session, snapshot_id)
    findings += disabled_rules(session, snapshot_id)
    if findings:
        session.execute(
            insert(Finding),
            [
                {
                    "snapshot_id": snapshot_id,
                    "kind": f.kind,
                    "severity": f.severity,
                    "policy_fmc_id": f.policy_fmc_id,
                    "title": f.title[:512],
                    "details": f.details,
                }
                for f in findings
            ],
        )
    session.execute(
        update(Snapshot).where(Snapshot.id == snapshot_id).values(analyzed_at=datetime.now(UTC))
    )
    summary: Counter[str] = Counter(f.kind for f in findings)
    return dict(summary)
