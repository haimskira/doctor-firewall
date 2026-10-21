"""Phase-2 analysis: match spaces, shadowing, dead rules, ACE expansion, rule score.

Runs after :func:`app.analysis.basic.analyze` in the same transaction and appends its
findings. Everything is read-only with respect to the FMC.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from app.analysis.assets import effective_assets
from app.analysis.basic import FindingRow
from app.analysis.connectivity import MapBuilder
from app.analysis.expand import Resolver, RuleSpace, rule_spaces
from app.analysis.score import ACE_HEAVY, PERMIT_ACTIONS, AssetIndex, RuleFacts, score_rule
from app.analysis.shadow import analyse_order
from app.core.config import Settings
from app.models.assets import ClusterSetting, RuleScore
from app.models.inventory import Cluster, ClusterPolicy, Finding, Policy, Rule, RuleRef, Snapshot

ORDERED_KINDS = ("access", "prefilter", "decryption")  # first-match rule lists
ACE_KINDS = ("access", "prefilter")  # rules that compile into Lina ACEs
ACE_WARNING_RATIO = 0.8


def load_assets(session: Session) -> AssetIndex:
    return AssetIndex(
        [(a.network, a.system, a.tier, a.user_type) for a in effective_assets(session)]
    )


def _rule_ref(rs: RuleSpace) -> dict[str, Any]:
    return {"id": rs.fmc_id, "name": rs.name, "index": rs.rule_index}


def _is_dead(rule: Rule, now: datetime, window: timedelta) -> bool:
    if rule.hit_count is None or not rule.enabled:
        return False  # hit counts not collected for this rule: no evidence
    if rule.hit_count == 0:
        return True
    return rule.last_hit is not None and rule.last_hit < now - window


def analyze_semantics(
    session: Session, snapshot_id: int, settings: Settings, now: datetime | None = None
) -> dict[str, int]:
    now = now or datetime.now(UTC)
    window = timedelta(days=settings.dead_rule_days)
    session.execute(delete(RuleScore).where(RuleScore.snapshot_id == snapshot_id))
    resolver = Resolver.load(session, snapshot_id)
    assets = load_assets(session)
    edges = MapBuilder(session, snapshot_id, assets)
    with_literals = set(
        session.scalars(
            select(RuleRef.rule_id)
            .where(RuleRef.snapshot_id == snapshot_id, RuleRef.literal.is_not(None))
            .distinct()
        )
    )
    findings: list[FindingRow] = []
    scores: list[dict[str, Any]] = []
    ace_by_policy: dict[str, int] = {}

    policies = session.scalars(
        select(Policy).where(Policy.snapshot_id == snapshot_id, Policy.kind.in_(ORDERED_KINDS))
    ).all()
    for policy in policies:
        spaces = rule_spaces(session, snapshot_id, policy.fmc_id, resolver)
        shadows, overlaps = analyse_order(spaces)
        shadowed_by = {s.rule.rule_id: s.by.fmc_id for s in shadows}
        for s in shadows:
            findings.append(
                FindingRow(
                    kind="shadowed_rule",
                    severity="high" if s.conflict else "medium",
                    policy_fmc_id=policy.fmc_id,
                    title=(
                        f"#{s.rule.rule_index} {s.rule.name} can never match: rule "
                        f"#{s.by.rule_index} {s.by.name} matches all of its traffic first"
                        + (" with a different verdict" if s.conflict else "")
                    ),
                    details={
                        "rule": _rule_ref(s.rule),
                        "by": _rule_ref(s.by),
                        "conflict": s.conflict,
                        "policy_kind": policy.kind,
                    },
                )
            )
        for o in overlaps:
            findings.append(
                FindingRow(
                    kind="overlap_conflict",
                    severity="low",
                    policy_fmc_id=policy.fmc_id,
                    title=(
                        f"#{o.rule.rule_index} {o.rule.name} partly overridden by "
                        f"#{o.with_rule.rule_index} {o.with_rule.name} (opposite verdict)"
                    ),
                    details={
                        "rule": _rule_ref(o.rule),
                        "with": _rule_ref(o.with_rule),
                        "policy_kind": policy.kind,
                    },
                )
            )
        if policy.kind == "access":
            edges.load_services(policy.fmc_id)
        if policy.kind in ACE_KINDS:
            ace_by_policy[policy.fmc_id] = sum(rs.ace_count for rs in spaces if rs.enabled)
        rules = {
            r.id: r
            for r in session.scalars(
                select(Rule).where(
                    Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id == policy.fmc_id
                )
            )
        }
        for rs in spaces:
            rule = rules[rs.rule_id]
            dead = policy.kind == "access" and _is_dead(rule, now, window)
            if dead:
                findings.append(
                    FindingRow(
                        kind="dead_rule",
                        severity="medium" if rule.action in PERMIT_ACTIONS else "low",
                        policy_fmc_id=policy.fmc_id,
                        title=(
                            f"#{rule.rule_index} {rule.name}: no hits"
                            + (
                                ""
                                if rule.hit_count == 0
                                else f" in the last {settings.dead_rule_days} days"
                            )
                        ),
                        details={
                            "rule": _rule_ref(rs),
                            "hit_count": rule.hit_count,
                            "last_hit": rule.last_hit.isoformat() if rule.last_hit else None,
                        },
                    )
                )
            if rs.enabled and rs.ace_count > ACE_HEAVY:
                findings.append(
                    FindingRow(
                        kind="ace_heavy_rule",
                        severity="low",
                        policy_fmc_id=policy.fmc_id,
                        title=f"#{rule.rule_index} {rule.name} expands to ~{rs.ace_count:,} ACEs",
                        details={
                            "rule": _rule_ref(rs),
                            "aces": rs.ace_count,
                            "leaves": rs.leaf_counts,
                        },
                    )
                )
            result = (
                score_rule(
                    RuleFacts(
                        action=rule.action,
                        enabled=rule.enabled,
                        src=rs.space.src_net,
                        dst=rs.space.dst_net,
                        dst_ports_any=rs.space.dst_port.any,
                        dst_port_count=rs.space.dst_port.port_count(),
                        apps_any=rs.space.token("app").any,
                        ips_policy=rule.ips_policy,
                        file_policy=rule.file_policy,
                        log_end=rule.log_end,
                        log_begin=rule.log_begin,
                        hit_count=rule.hit_count,
                        dead=dead,
                        shadowed_by=shadowed_by.get(rs.rule_id),
                        has_literals=rs.rule_id in with_literals,
                        ace_count=rs.ace_count,
                    ),
                    assets,
                )
                if policy.kind == "access"
                else None
            )
            if result is not None and result.score is not None and rs.rule_id not in shadowed_by:
                # Only rules that can match carry traffic on the map.
                edges.add(
                    policy_id=policy.fmc_id,
                    rule={"id": rs.fmc_id, "name": rs.name, "index": rs.rule_index},
                    rule_id=rs.rule_id,
                    src=rs.space.src_net,
                    dst=rs.space.dst_net,
                    reasons=(str(r["code"]) for r in result.reasons),
                    score=result.score,
                    hits=rule.hit_count,
                )
            scores.append(
                {
                    "rule_id": rs.rule_id,
                    "snapshot_id": snapshot_id,
                    "score": result.score if result else None,
                    "ace_count": rs.ace_count,
                    "reasons": result.reasons if result else [],
                    "src_tiers": result.src_tiers if result else [],
                    "dst_tiers": result.dst_tiers if result else [],
                    "shadowed_by": shadowed_by.get(rs.rule_id),
                    "dead": dead,
                }
            )

    ace_totals = _cluster_aces(session, snapshot_id, settings, ace_by_policy, findings)
    edge_count = edges.flush()
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
    if scores:
        session.execute(insert(RuleScore), scores)
    snap = session.get(Snapshot, snapshot_id)
    if snap is not None:
        session.execute(
            update(Snapshot)
            .where(Snapshot.id == snapshot_id)
            .values(
                stats={
                    **snap.stats,
                    "ace_by_cluster": ace_totals,
                    "assets_used": len(assets),
                    "map_edges": edge_count,
                }
            )
        )
    return dict(Counter(f.kind for f in findings))


def _cluster_aces(
    session: Session,
    snapshot_id: int,
    settings: Settings,
    ace_by_policy: dict[str, int],
    findings: list[FindingRow],
) -> dict[str, int]:
    """Sum the ACEs of every access / prefilter policy governing each cluster."""
    governing: dict[str, set[str]] = defaultdict(set)
    for cluster_id, policy_id in session.execute(
        select(ClusterPolicy.cluster_fmc_id, ClusterPolicy.policy_fmc_id).where(
            ClusterPolicy.snapshot_id == snapshot_id
        )
    ).all():
        governing[cluster_id].add(policy_id)
    limits = {s.cluster_fmc_id: s for s in session.scalars(select(ClusterSetting))}
    totals: dict[str, int] = {}
    for cluster in session.scalars(select(Cluster).where(Cluster.snapshot_id == snapshot_id)):
        total = sum(ace_by_policy.get(p, 0) for p in governing.get(cluster.fmc_id, set()))
        totals[cluster.fmc_id] = total
        setting = limits.get(cluster.fmc_id)
        limit = setting.ace_limit if setting else settings.default_ace_limit
        verified = bool(setting and setting.ace_limit_verified)
        if total > limit * ACE_WARNING_RATIO:
            findings.append(
                FindingRow(
                    kind="ace_cluster_limit",
                    severity="high" if total > limit else "medium",
                    title=(
                        f"{cluster.name}: ~{total:,} ACEs, {total * 100 // limit}% of the "
                        f"{'verified' if verified else 'unverified default'} limit {limit:,}"
                    ),
                    details={
                        "cluster": {"id": cluster.fmc_id, "name": cluster.name},
                        "aces": total,
                        "limit": limit,
                        "limit_verified": verified,
                    },
                )
            )
    return totals
