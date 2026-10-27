"""Compact network groups: the same addresses with fewer members (fewer ACEs).

The FMC flattens every group into one ACE per address leaf, multiplied across the rule's
fields. A group holding ``10.30.14.0/24`` *and* forty hosts inside it, or forty consecutive
hosts, matches no more than one network or one range — but costs forty times the ACEs in every
rule that uses it. ``compact_group`` rewrites such a group:

1. **Covered members go** — a direct address member (host / network / range object or literal)
   whose addresses are all inside the group's other members (direct or nested) is removed.
   The smallest members are tried first, so the covering network stays and the hosts go.
2. **Consecutive members merge** — the remaining direct address members that touch or overlap
   are replaced by one object per merged block: a host, a network when the block is exactly one
   CIDR, otherwise a range (an existing object with that exact value is reused).

The group's address set is unchanged, so every rule, NAT or route that uses it matches exactly
the same traffic (the traffic proof checks it before and after writing). Nested groups, FQDNs and
other members are never touched. The ACE saving is an estimate over the access / prefilter
rules that use the group directly or through any parent group.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left
from collections import deque
from dataclasses import dataclass
from typing import Any

from app.analysis.expand import ACE_FIELDS, literal_leaves
from app.analysis.naming import MAX_NAME, disambiguate
from app.analysis.recommend import (
    ADDRESS_KINDS,
    Draft,
    Estate,
    Obj,
    Ref,
    RuleInfo,
    _object_target,
    _plan,
    proposed_object_name,
)
from app.analysis.space import AddressSet

Interval = tuple[int, int, int]  # (ip version, first, last)
MAX_MEMBERS = 5000  # larger groups are left alone (bounded work per analysis)
MAX_ANCESTOR_DEPTH = 16


@dataclass
class _Member:
    ref: Ref
    intervals: list[Interval]
    candidate: bool  # a direct address member this proposal may remove or merge

    @property
    def size(self) -> int:
        return sum(hi - lo + 1 for _, lo, hi in self.intervals)


def _intervals(values: set[str] | list[str]) -> list[Interval]:
    s = AddressSet.build(values)
    return [(4, lo, hi) for lo, hi in s.v4] + [(6, lo, hi) for lo, hi in s.v6]


def _member(estate: Estate, ref: Ref) -> _Member:
    if ref.object_id is None:
        if ref.literal is not None and ref.literal_kind in ("address", "range"):
            values = literal_leaves(ref.literal, ref.literal_kind).addresses
            return _Member(ref, _intervals(values), True)
        return _Member(ref, [], False)
    obj = estate.objects.get(ref.object_id)
    if obj is not None and obj.kind in ADDRESS_KINDS and obj.value and not obj.stub:
        return _Member(ref, _intervals([obj.value]), True)
    # Nested groups (and anything else that resolves to addresses) cover, never change.
    leaves = estate.resolver.leaves(ref.object_id)
    return _Member(ref, _intervals(leaves.addresses), False)


def _drop_covered(members: list[_Member]) -> list[_Member]:
    """Remove candidates whose every address another remaining member also covers."""
    points: dict[int, set[int]] = {4: set(), 6: set()}
    for m in members:
        for version, lo, hi in m.intervals:
            points[version].update((lo, hi + 1))
    bounds = {v: sorted(p) for v, p in points.items()}
    counts = {v: [0] * len(bounds[v]) for v in bounds}

    def segments(version: int, lo: int, hi: int) -> range:
        b = bounds[version]
        return range(bisect_left(b, lo), bisect_left(b, hi + 1))

    for m in members:
        for version, lo, hi in m.intervals:
            for i in segments(version, lo, hi):
                counts[version][i] += 1
    removed: list[_Member] = []
    order = sorted(
        (m for m in members if m.candidate and m.intervals), key=lambda m: (m.size, m.ref.label)
    )
    for m in order:
        if all(
            counts[version][i] >= 2
            for version, lo, hi in m.intervals
            for i in segments(version, lo, hi)
        ):
            for version, lo, hi in m.intervals:
                for i in segments(version, lo, hi):
                    counts[version][i] -= 1
            removed.append(m)
    return removed


def _block_value(version: int, lo: int, hi: int) -> tuple[str, str]:
    """(object kind, canonical value) for one merged block."""
    ip: type[ipaddress.IPv4Address] | type[ipaddress.IPv6Address] = (
        ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    )
    bits = 32 if version == 4 else 128
    size = hi - lo + 1
    if size == 1:
        return "host", f"{ip(lo)}/{bits}"
    if size & (size - 1) == 0 and lo % size == 0:
        return "network", f"{ip(lo)}/{bits - size.bit_length() + 1}"
    return "range", f"{ip(lo)}-{ip(hi)}"


def _merge_blocks(members: list[_Member]) -> list[tuple[tuple[str, str], list[_Member]]]:
    """Group the remaining candidates into touching / overlapping blocks."""
    spans = sorted(
        ((version, lo, hi, m) for m in members for version, lo, hi in m.intervals),
        key=lambda x: (x[0], x[1], x[2]),
    )
    blocks: list[list[Any]] = []  # [version, lo, hi, members]
    for version, lo, hi, m in spans:
        last = blocks[-1] if blocks else None
        if last is not None and last[0] == version and lo <= last[2] + 1:
            last[2] = max(last[2], hi)
            if m not in last[3]:
                last[3].append(m)
        else:
            blocks.append([version, lo, hi, [m]])
    return [(_block_value(v, lo, hi), ms) for v, lo, hi, ms in blocks]


def _ancestors(estate: Estate, gid: str) -> set[str]:
    found: set[str] = set()
    queue = deque([(gid, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= MAX_ANCESTOR_DEPTH:
            continue
        for parent in estate.parents.get(current, set()):
            if parent not in found:
                found.add(parent)
                queue.append((parent, depth + 1))
    return found


def _ace_delta(
    estate: Estate,
    infos: dict[int, RuleInfo],
    gid: str,
    old: set[str],
    new: set[str],
) -> tuple[int, int, set[int]]:
    """(estimated ACE change, rules whose ACEs change, every rule using the group) of the
    group's leaves going ``old`` -> ``new``."""
    holders = {gid} | _ancestors(estate, gid)
    rule_ids = set().union(*(estate.rule_users.get(h, set()) for h in holders))
    removed, added = old - new, new - old
    delta = rules = 0
    for rid in rule_ids:
        info = infos.get(rid)
        if info is None or info.ace <= 0:
            continue
        ace = float(info.ace)
        changed = False
        for fld in ACE_FIELDS:
            refs = info.refs.get(fld, [])
            if not any(r.object_id in holders for r in refs):
                continue
            leaves = info.leaves.get(fld)
            if leaves is None:
                continue
            others: set[str] = set()
            for r in refs:
                if r.object_id in holders:
                    continue
                if r.object_id is not None:
                    others |= estate.resolver.leaves(r.object_id).addresses
                elif r.literal is not None:
                    others |= literal_leaves(r.literal, r.literal_kind).addresses
            after = (leaves.addresses - (removed - others)) | added
            before_count = max(1, leaves.count())
            after_count = max(1, before_count - len(leaves.addresses) + len(after))
            if after_count != before_count:
                ace = ace * after_count / before_count
                changed = True
        if changed:
            delta += round(ace) - info.ace
            rules += 1
    return delta, rules, rule_ids


def recommend_compact_groups(
    estate: Estate, infos: dict[int, RuleInfo], skip: set[str]
) -> list[Draft]:
    """``infos``: every access / prefilter rule by database id; ``skip``: groups another
    recommendation already rewrites (one group update per analysis keeps them independent)."""
    taken = {o.name for o in estate.objects.values()}
    drafts: list[Draft] = []
    for group in sorted(estate.objects.values(), key=lambda o: o.name):
        if group.kind != "network_group" or group.fixed or group.fmc_id in skip:
            continue
        refs = estate.members.get(group.fmc_id, [])
        if len(refs) < 2 or len(refs) > MAX_MEMBERS:
            continue
        members = [_member(estate, r) for r in refs]
        covered = _drop_covered(members)
        gone = {id(m) for m in covered}
        remaining = [m for m in members if m.candidate and id(m) not in gone]
        blocks = _merge_blocks(remaining)
        merged = [(value, ms) for value, ms in blocks if len(ms) > 1]
        if not covered and not merged:
            continue
        created: list[str] = []  # names of the objects the plan creates
        replacement: dict[int, Ref | None] = {}  # id(member) -> new ref (first) / None (gone)
        new_labels: list[dict[str, Any]] = []
        local_taken = set(taken)
        summaries: list[tuple[Obj | None, str, str, str]] = []
        for (kind, value), ms in merged:
            existing = estate.existing_object(kind, value)
            if existing is not None:
                name = existing.name
            else:
                proposed = proposed_object_name(estate, kind, value)
                if proposed is None:
                    continue
                name = disambiguate(proposed[:MAX_NAME], local_taken)
                local_taken.add(name)
                created.append(name)
            summaries.append((existing, kind, value, name))
            first, *rest = sorted(ms, key=lambda m: refs.index(m.ref))
            replacement[id(first)] = Ref(existing.fmc_id if existing else None, name)
            for m in rest:
                replacement[id(m)] = None
            new_labels.append(
                {
                    "id": existing.fmc_id if existing else None,
                    "name": name,
                    "kind": kind,
                    "value": value,
                    "members": [m.ref.label for m in ms],
                    "status": "kept" if existing else "new",
                }
            )
        for m in covered:
            replacement[id(m)] = None
        if not replacement:
            continue
        taken |= set(created)

        def build(
            pb: Any,
            group: Obj = group,
            members: list[_Member] = members,
            replacement: dict[int, Ref | None] = replacement,
            summaries: list[tuple[Obj | None, str, str, str]] = summaries,
        ) -> None:
            made: dict[str, dict[str, Any]] = {}
            for existing, kind, value, name in summaries:
                made[name] = (
                    estate.obj_json(existing)
                    if existing is not None
                    else pb.create_object(kind, name, value=value)
                )
            new_refs: list[dict[str, Any]] = []
            for m in members:
                if id(m) not in replacement:
                    new_refs.append(estate.ref_json(m.ref))
                elif (ref := replacement[id(m)]) is not None:
                    new_refs.append(made[ref.name])
            pb.update_group(
                estate.obj_json(group), estate.refs_json([m.ref for m in members]), new_refs
            )

        kept_refs: list[str] = []
        for m in members:
            if id(m) not in replacement:
                kept_refs.append(m.ref.label)
            elif (ref := replacement[id(m)]) is not None:
                kept_refs.append(ref.name)
        old_leaves = estate.resolver.leaves(group.fmc_id).addresses
        new_leaves = _leaves_after(estate, members, replacement, summaries)
        ace_delta, rules, users = _ace_delta(estate, infos, group.fmc_id, old_leaves, new_leaves)
        removed_count = len(members) - len(kept_refs)
        title = f"{group.name}: {len(members)} -> {len(kept_refs)} members, same addresses" + (
            f" (~{ace_delta:,} ACEs in {rules} rule(s))" if ace_delta else ""
        )
        drafts.append(
            Draft(
                kind="compact_group",
                principle="ace_economy",
                title=title,
                priority=40 if ace_delta <= -1000 else 30 if ace_delta < 0 else 15,
                display="split",
                deploy_cost=1 + len(created),
                targets=[_object_target(group)],
                preview={
                    "objects": {
                        "before": [
                            {
                                "id": group.fmc_id,
                                "name": group.name,
                                "kind": group.kind,
                                "members": [m.ref.label for m in members],
                                "status": "unchanged",
                            }
                        ],
                        "after": [
                            {
                                "id": group.fmc_id,
                                "name": group.name,
                                "kind": group.kind,
                                "members": kept_refs,
                                "status": "modified",
                            },
                            *new_labels,
                        ],
                    },
                    "compact": {
                        "covered": [m.ref.label for m in covered],
                        "merged": [
                            {"into": n["name"], "value": n["value"], "members": n["members"]}
                            for n in new_labels
                        ],
                        "members_before": len(members),
                        "members_after": len(kept_refs),
                        "removed": removed_count,
                        "rules": rules,
                    },
                    "affected_rules": {"total": len(users), "sample": estate.rule_sample(users)},
                },
                ace_delta=ace_delta,
                plan=_plan(build),
            )
        )
    return drafts


def _leaves_after(
    estate: Estate,
    members: list[_Member],
    replacement: dict[int, Ref | None],
    summaries: list[tuple[Obj | None, str, str, str]],
) -> set[str]:
    """The group's address leaves after the rewrite (nested groups unchanged)."""
    out: set[str] = {value for _, _, value, _ in summaries}
    for m in members:
        if id(m) in replacement:
            continue
        if m.ref.object_id is not None:
            out |= estate.resolver.leaves(m.ref.object_id).addresses
        elif m.ref.literal is not None:
            out |= literal_leaves(m.ref.literal, m.ref.literal_kind).addresses
    return out
