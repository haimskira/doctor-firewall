"""Redundant membership: the same object reachable twice where once is enough.

* ``remove_redundant_reference`` — a rule field references both a group and an object (or
  group) that is already a member of it, directly or through any chain of nested groups. The
  group already matches it: the extra reference is removed from the rule.
* ``remove_redundant_member`` — a group contains a member directly and also through one of its
  nested groups: the direct copy is removed.

Both are decided on group membership only (not on address arithmetic), so the matched traffic is
exactly the same before and after; the fix only removes noise, duplicate ACEs and the confusion
of "which level is this rule really using?".
"""

from __future__ import annotations

from collections import deque
from typing import Any

from app.analysis.recommend import (
    Draft,
    Estate,
    RuleInfo,
    _object_target,
    _plan,
    _policy_ref,
    _rule_dict,
    _rule_priority,
    _rule_target,
    rule_view,
    with_status,
)
from app.models.inventory import Policy

MAX_DEPTH = 16  # deeper than any sane design; cycles are cut by the visited set
REF_FIELDS = (
    "src_net",
    "dst_net",
    "src_port",
    "dst_port",
    "src_zone",
    "dst_zone",
    "url",
    "src_sgt",
    "dst_sgt",
)


def member_paths(estate: Estate, group_id: str) -> dict[str, list[str]]:
    """Every object reachable inside a group -> the shortest chain of names leading to it."""
    found: dict[str, list[str]] = {}
    queue: deque[tuple[str, list[str], int]] = deque([(group_id, [], 0)])
    seen = {group_id}
    while queue:
        current, path, depth = queue.popleft()
        if depth >= MAX_DEPTH:
            continue
        for member in estate.members.get(current, []):
            oid = member.object_id
            if oid is None or oid in seen:
                continue
            seen.add(oid)
            chain = [*path, member.name]
            found[oid] = chain
            queue.append((oid, chain, depth + 1))
    return found


def _cached_paths(
    estate: Estate, cache: dict[str, dict[str, list[str]]], gid: str
) -> dict[str, list[str]]:
    if gid not in cache:
        cache[gid] = member_paths(estate, gid)
    return cache[gid]


def recommend_redundant_references(
    estate: Estate, policy: Policy, rules: list[RuleInfo]
) -> list[Draft]:
    cache: dict[str, dict[str, list[str]]] = {}
    drafts: list[Draft] = []
    for info in rules:
        new_refs = {f: list(v) for f, v in info.refs.items()}
        why: list[dict[str, Any]] = []
        for fld in REF_FIELDS:
            refs = info.refs.get(fld, [])
            groups = [
                r for r in refs if r.object_id is not None and estate.members.get(r.object_id)
            ]
            if not groups:
                continue
            keep = []
            for ref in refs:
                container = next(
                    (
                        (g, _cached_paths(estate, cache, g.object_id or "")[ref.object_id])
                        for g in groups
                        if ref.object_id is not None
                        and g.object_id != ref.object_id
                        and ref.object_id in _cached_paths(estate, cache, g.object_id or "")
                    ),
                    None,
                )
                if container is None:
                    keep.append(ref)
                    continue
                group, chain = container
                why.append(
                    {
                        "field": fld,
                        "removed": ref.name,
                        "kept": group.name,
                        "chain": [group.name, *chain],
                    }
                )
            new_refs[fld] = keep
        if not why:
            continue
        r = info.rule
        changed = sorted({w["field"] for w in why})
        before = rule_view(info)
        after = with_status(rule_view(info, new_refs), "modified", before)
        drafts.append(
            Draft(
                kind="remove_redundant_reference",
                principle="no_redundant_membership",
                title=(
                    f"#{r.rule_index} {r.name}: remove "
                    + ", ".join(sorted({w["removed"] for w in why}))
                    + " — already inside "
                    + ", ".join(sorted({w["kept"] for w in why}))
                ),
                priority=_rule_priority(35, info),
                display="inline",
                deploy_cost=1,
                targets=[_rule_target(info)],
                preview={
                    "policy": _policy_ref(policy),
                    "before": [before],
                    "after": [after],
                    "redundant": why,
                },
                policy_fmc_id=policy.fmc_id,
                plan=_plan(
                    lambda pb, info=info, new_refs=new_refs, changed=changed: pb.update_rule(
                        _rule_dict(info),
                        {f: estate.refs_json(info.refs.get(f, [])) for f in changed},
                        {f: estate.refs_json(new_refs[f]) for f in changed},
                    )
                ),
            )
        )
    return drafts


def recommend_redundant_members(estate: Estate) -> list[Draft]:
    cache: dict[str, dict[str, list[str]]] = {}
    drafts: list[Draft] = []
    for group in sorted(estate.objects.values(), key=lambda o: o.name):
        members = estate.members.get(group.fmc_id, [])
        nested = [m for m in members if m.object_id is not None and estate.members.get(m.object_id)]
        if group.fixed or not nested:
            continue
        keep = []
        why: list[dict[str, Any]] = []
        for m in members:
            via = next(
                (
                    (n, _cached_paths(estate, cache, n.object_id or "")[m.object_id])
                    for n in nested
                    if m.object_id is not None
                    and n.object_id != m.object_id
                    and m.object_id in _cached_paths(estate, cache, n.object_id or "")
                ),
                None,
            )
            if via is None:
                keep.append(m)
            else:
                why.append(
                    {"removed": m.name, "kept": via[0].name, "chain": [via[0].name, *via[1]]}
                )
        if not why:
            continue
        drafts.append(
            Draft(
                kind="remove_redundant_member",
                principle="no_redundant_membership",
                title=(
                    f"{group.name}: remove "
                    + ", ".join(w["removed"] for w in why)
                    + " — already inside "
                    + ", ".join(sorted({w["kept"] for w in why}))
                ),
                priority=30,
                display="split",
                deploy_cost=1,
                targets=[_object_target(group)],
                preview={
                    "objects": {
                        "before": [
                            {
                                "id": group.fmc_id,
                                "name": group.name,
                                "kind": group.kind,
                                "members": [m.label for m in members],
                                "status": "unchanged",
                            }
                        ],
                        "after": [
                            {
                                "id": group.fmc_id,
                                "name": group.name,
                                "kind": group.kind,
                                "members": [m.label for m in keep],
                                "status": "modified",
                            }
                        ],
                    },
                    "redundant": why,
                },
                plan=_plan(
                    lambda pb, group=group, members=members, keep=keep: pb.update_group(
                        estate.obj_json(group), estate.refs_json(members), estate.refs_json(keep)
                    )
                ),
            )
        )
    return drafts
