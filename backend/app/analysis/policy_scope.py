"""Which access policies each finding and recommendation belongs to.

An access policy is a world of its own: its rules, the policies it links (prefilter,
decryption ...), and every object those rules use — directly or through any group. A rule
finding belongs to its policy (a prefilter or decryption rule also to the access policies
linking its policy); an object finding or recommendation belongs to every policy whose rules use
one of its objects; a cluster finding to the policies the cluster enforces. An object no rule
uses belongs to no policy: it is shown only for all policies together.

The result is stored as ``policy_ids`` on findings and recommendations, and the number of
objects of each policy in the snapshot's stats (``objects_by_policy``).
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.inventory import (
    ClusterPolicy,
    Finding,
    GroupMember,
    Policy,
    Rule,
    RuleRef,
    Snapshot,
)
from app.models.recommendations import Recommendation


class PolicyIndex:
    """Every id a finding or recommendation may name -> the access policies it belongs to."""

    def __init__(self, session: Session, snapshot_id: int) -> None:
        sid = snapshot_id
        access: set[str] = set()
        linked: dict[str, set[str]] = defaultdict(set)  # prefilter, SSL ... -> access policies
        for fmc_id, kind, links in session.execute(
            select(Policy.fmc_id, Policy.kind, Policy.links).where(Policy.snapshot_id == sid)
        ):
            if kind != "access":
                continue
            access.add(fmc_id)
            for link in links or []:
                if link.get("id"):
                    linked[str(link["id"])].add(fmc_id)
        self.access = access
        self.by_policy: dict[str, frozenset[str]] = {p: frozenset({p}) for p in access}
        for other, linking in linked.items():
            self.by_policy[other] = frozenset(linking)

        self.by_rule: dict[str, frozenset[str]] = {}
        rule_policy: dict[int, frozenset[str]] = {}
        for rid, fmc_id, policy in session.execute(
            select(Rule.id, Rule.fmc_id, Rule.policy_fmc_id).where(Rule.snapshot_id == sid)
        ):
            mine = self.by_policy.get(policy, frozenset())
            rule_policy[rid] = mine
            self.by_rule[fmc_id] = mine | self.by_rule.get(fmc_id, frozenset())

        objects: dict[str, set[str]] = defaultdict(set)
        for rid, oid in session.execute(
            select(RuleRef.rule_id, RuleRef.object_fmc_id).where(
                RuleRef.snapshot_id == sid, RuleRef.object_fmc_id.is_not(None)
            )
        ):
            if oid is not None:
                objects[oid] |= rule_policy.get(rid, frozenset())
        members: dict[str, list[str]] = defaultdict(list)
        for gid, mid in session.execute(
            select(GroupMember.group_fmc_id, GroupMember.member_fmc_id).where(
                GroupMember.snapshot_id == sid, GroupMember.member_fmc_id.is_not(None)
            )
        ):
            if mid is not None:
                members[gid].append(mid)
        # A group's policies reach every member, nested to any depth (cycles stop by themselves).
        queue = deque(oid for oid, owners in objects.items() if owners)
        while queue:
            gid = queue.popleft()
            for mid in members.get(gid, ()):
                if not objects[gid] <= objects[mid]:
                    objects[mid] |= objects[gid]
                    queue.append(mid)
        self.by_object = {oid: frozenset(owners) for oid, owners in objects.items() if owners}

        clusters: dict[str, set[str]] = defaultdict(set)
        for cluster, policy in session.execute(
            select(ClusterPolicy.cluster_fmc_id, ClusterPolicy.policy_fmc_id).where(
                ClusterPolicy.snapshot_id == sid
            )
        ):
            if policy in access:
                clusters[cluster].add(policy)
        self.by_cluster = {c: frozenset(p) for c, p in clusters.items()}

    def lookup(self, value: str) -> frozenset[str]:
        for table in (self.by_object, self.by_rule, self.by_policy, self.by_cluster):
            found = table.get(value)
            if found is not None:
                return found
        return frozenset()

    def of(self, policy: str | None, *documents: Any) -> list[str]:
        """The policies of an item: its own policy's, else those of every id it names."""
        if policy is not None:
            return sorted(self.by_policy.get(policy, frozenset()))
        found: set[str] = set()
        for value in _strings(documents):
            found |= self.lookup(value)
        return sorted(found)

    def object_counts(self) -> dict[str, int]:
        counts: dict[str, int] = dict.fromkeys(self.access, 0)
        for owners in self.by_object.values():
            for p in owners:
                counts[p] += 1
        return counts


def _strings(documents: Iterable[Any]) -> Iterable[str]:
    stack = list(documents)
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list | tuple):
            stack.extend(item)


def assign(session: Session, snapshot_id: int) -> None:
    """Store ``policy_ids`` on every finding and recommendation of the snapshot. Caller commits."""
    index = PolicyIndex(session, snapshot_id)
    findings = [
        {"id": fid, "ids": index.of(policy, details)}
        for fid, policy, details in session.execute(
            select(Finding.id, Finding.policy_fmc_id, Finding.details).where(
                Finding.snapshot_id == snapshot_id
            )
        )
    ]
    recommendations = [
        {"id": rid, "ids": index.of(policy, targets, preview)}
        for rid, policy, targets, preview in session.execute(
            select(
                Recommendation.id,
                Recommendation.policy_fmc_id,
                Recommendation.targets,
                Recommendation.preview,
            ).where(Recommendation.snapshot_id == snapshot_id)
        )
    ]
    for model, rows in ((Finding, findings), (Recommendation, recommendations)):
        if rows:
            session.execute(
                update(model),
                [{"id": r["id"], "policy_ids": r["ids"]} for r in rows],
            )
    snap = session.get(Snapshot, snapshot_id)
    if snap is not None:
        session.execute(
            update(Snapshot)
            .where(Snapshot.id == snapshot_id)
            .values(stats={**snap.stats, "objects_by_policy": index.object_counts()})
        )
