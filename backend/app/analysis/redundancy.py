"""Redundant membership: the same object reachable twice where once is enough.

* ``remove_redundant_reference`` — a rule field references both a group and an object (or
  group) that is already a member of it, directly or through any chain of nested groups. The
  group already matches it: the extra reference is removed from the rule.
* ``remove_redundant_member`` — a group contains a member directly and also through one of its
  nested groups: the direct copy is removed.

Both are decided on group membership only (not on address arithmetic), so the matched traffic is
exactly the same before and after; the fix only removes noise, duplicate ACEs and the confusion
of "which level is this rule really using?".

Safety: a group in a membership cycle, or marked overridable (other members per device), never
stands for what it contains and is never edited; a reference is only removed while the group
containing it stays; a rule field or a group is never emptied (an empty field means "any").
"""

from __future__ import annotations

from collections import deque
from typing import Any

from app.analysis.expand import rule_conditions
from app.analysis.recommend import (
    Draft,
    Estate,
    Ref,
    RuleInfo,
    _object_target,
    _plan,
    _policy_ref,
    _rule_dict,
    _rule_priority,
    _rule_target,
    rule_view,
    shadowed,
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
    """Every object reachable inside a group -> the shortest chain of names leading to it.

    Overridable groups are reached but not entered: their members may differ per device."""
    found: dict[str, list[str]] = {}
    queue: deque[tuple[str, list[str], int]] = deque([(group_id, [], 0)])
    seen = {group_id}
    while queue:
        current, path, depth = queue.popleft()
        if depth >= MAX_DEPTH:
            continue
        holder = estate.objects.get(current)
        if current != group_id and holder is not None and holder.overridable:
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


def _container(estate: Estate, ref: Ref) -> bool:
    """A group that may stand for its members: not cyclic, not overridable, not empty."""
    oid = ref.object_id
    if oid is None or not estate.members.get(oid) or oid in estate.cyclic_groups():
        return False
    obj = estate.objects.get(oid)
    return obj is None or not obj.overridable


def redundant(
    estate: Estate, cache: dict[str, dict[str, list[str]]], refs: list[Ref]
) -> tuple[list[Ref], list[tuple[Ref, Ref, list[str]]]]:
    """(kept refs, [(removed ref, kept group containing it, chain)]) of one rule field or of
    the members of one group. A reference goes only if a group that stays in the same list
    contains it, and the list is never emptied (then nothing goes)."""
    containers = [i for i, r in enumerate(refs) if _container(estate, r)]
    options: dict[int, list[int]] = {}
    for i, ref in enumerate(refs):
        if ref.object_id is None:
            continue
        found = [
            g
            for g in containers
            if g != i
            and refs[g].object_id != ref.object_id
            and ref.object_id in _cached_paths(estate, cache, refs[g].object_id or "")
        ]
        if found:
            options[i] = found
    removed: dict[int, int] = {i: found[0] for i, found in options.items()}
    changed = True
    while changed:  # a container that is removed itself cannot justify a removal
        changed = False
        for i in sorted(removed):
            if i not in removed or removed[i] not in removed:
                continue
            kept = [g for g in options[i] if g not in removed]
            if kept:
                removed[i] = kept[0]
            else:
                del removed[i]
            changed = True
    if not removed or len(removed) == len(refs):
        return list(refs), []
    gone: list[tuple[Ref, Ref, list[str]]] = []
    for i, g in sorted(removed.items()):
        paths = _cached_paths(estate, cache, refs[g].object_id or "")
        gone.append((refs[i], refs[g], paths[refs[i].object_id or ""]))
    return [r for i, r in enumerate(refs) if i not in removed], gone


def recommend_redundant_references(
    estate: Estate, policy: Policy, rules: list[RuleInfo]
) -> list[Draft]:
    cache: dict[str, dict[str, list[str]]] = {}
    drafts: list[Draft] = []
    for info in rules:
        if shadowed(info):
            continue  # removed instead
        new_refs = {f: list(v) for f, v in info.refs.items()}
        why: list[dict[str, Any]] = []
        held = set(rule_conditions(info.rule.attrs))
        for fld in REF_FIELDS:
            if fld in held:
                continue  # writing the field back would drop its unmodelled conditions
            keep, gone = redundant(estate, cache, info.refs.get(fld, []))
            for ref, group, chain in gone:
                why.append(
                    {
                        "field": fld,
                        "removed": ref.name,
                        "kept": group.name,
                        "chain": [group.name, *chain],
                    }
                )
            if gone:
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
        if group.fixed or group.overridable or group.fmc_id in estate.cyclic_groups():
            continue
        if not any(_container(estate, m) for m in members):
            continue
        keep, gone = redundant(estate, cache, members)
        why: list[dict[str, Any]] = [
            {"removed": m.name, "kept": via.name, "chain": [via.name, *chain]}
            for m, via, chain in gone
        ]
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
