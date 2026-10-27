"""Object relations: everything that ties one object (or group) into the rulebase.

For an object X: the groups containing it at any depth (the chains), the members it contains
when it is a group, every rule that uses X or any group of its chains (and through which level),
the address objects overlapping it, and the redundancies found on the way — a rule using both a
group and something already inside it, a group containing X directly and again through a nested
group — each linked to the recommendation that fixes it.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel
from sqlalchemy import func, literal, select
from sqlalchemy.orm import Session

from app.analysis.space import AddressSet
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_db
from app.models.inventory import FwObject, GroupMember, Policy, Rule, RuleRef
from app.models.recommendations import Recommendation

router = APIRouter(prefix="/api", tags=["relations"])

DbDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[Principal, Depends(require(Permission.POLICY_READ))]
FmcIdPath = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]

MAX_DEPTH = 16
MAX_DESCENDANTS = 200
MAX_RULES = 300
MAX_OVERLAPS = 40
ADDRESS_KINDS = ("host", "network", "range")


class RelNode(BaseModel):
    id: str
    kind: str  # object kind, or "rule"
    label: str
    role: str  # self | ancestor | descendant | rule | overlap
    depth: int  # ancestors > 0, descendants < 0, rules: deepest via + 1
    detail: str = ""


class RelEdge(BaseModel):
    source: str
    target: str
    kind: str  # member (child -> group) | uses (object -> rule) | overlap
    label: str = ""


class RelIssue(BaseModel):
    kind: str  # redundant_reference | redundant_member
    where_id: str  # rule id or group id
    where_name: str
    removed: str
    kept: str
    recommendation_id: int | None


class Relations(BaseModel):
    object: dict[str, Any]
    nodes: list[RelNode]
    edges: list[RelEdge]
    issues: list[RelIssue]
    truncated: bool


def _walk(db: Session, snapshot_id: int, start: str, *, up: bool) -> list[tuple[str, str, int]]:
    """(group, child, depth) edges above (``up``) or below the object, shortest depth."""
    near = GroupMember.member_fmc_id if up else GroupMember.group_fmc_id
    base = select(
        GroupMember.group_fmc_id.label("gid"),
        GroupMember.member_fmc_id.label("child"),
        literal(1).label("depth"),
    ).where(
        GroupMember.snapshot_id == snapshot_id,
        near == start,
        GroupMember.member_fmc_id.is_not(None),
    )
    tree = base.cte("tree", recursive=True)
    link = tree.c.gid if up else tree.c.child
    step = (
        select(GroupMember.group_fmc_id, GroupMember.member_fmc_id, tree.c.depth + 1)
        .join(tree, near == link)
        .where(
            GroupMember.snapshot_id == snapshot_id,
            GroupMember.member_fmc_id.is_not(None),
            tree.c.depth < MAX_DEPTH,
        )
    )
    tree = tree.union(step)
    rows = db.execute(
        select(tree.c.gid, tree.c.child, func.min(tree.c.depth))
        .group_by(tree.c.gid, tree.c.child)
        .order_by(func.min(tree.c.depth))
    )
    return [(str(g), str(c), int(d)) for g, c, d in rows if g is not None and c is not None]


def _reaches(edges: list[tuple[str, str, int]], start: str) -> dict[str, set[str]]:
    """node -> every group above it (from child -> group edges)."""
    up: dict[str, set[str]] = defaultdict(set)
    for g, c, _ in edges:
        up[c].add(g)
    closure: dict[str, set[str]] = {}

    def above(node: str, seen: frozenset[str]) -> set[str]:
        if node in closure:
            return closure[node]
        out: set[str] = set()
        for g in up.get(node, ()):
            if g in seen:
                continue
            out |= {g} | above(g, seen | {g})
        closure[node] = out
        return out

    for node in {start, *(c for _, c, _ in edges), *(g for g, _, _ in edges)}:
        above(node, frozenset({node}))
    return closure


@router.get("/snapshots/{snapshot_id}/objects/{object_id}/relations", response_model=Relations)
def object_relations(snapshot_id: int, object_id: FmcIdPath, db: DbDep, _: ReaderDep) -> Relations:
    obj = db.scalar(
        select(FwObject).where(FwObject.snapshot_id == snapshot_id, FwObject.fmc_id == object_id)
    )
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    up = _walk(db, snapshot_id, object_id, up=True)
    down = _walk(db, snapshot_id, object_id, up=False)
    truncated = len(down) > MAX_DESCENDANTS
    down = down[:MAX_DESCENDANTS]
    ids = {object_id} | {g for g, _, _ in up} | {c for _, c, _ in down}
    info = {
        fid: (name, kind, value)
        for fid, name, kind, value in db.execute(
            select(FwObject.fmc_id, FwObject.name, FwObject.kind, FwObject.value).where(
                FwObject.snapshot_id == snapshot_id, FwObject.fmc_id.in_(ids)
            )
        ).all()
    }

    def label(fid: str) -> str:
        return info.get(fid, (fid, "", None))[0]

    nodes: dict[str, RelNode] = {
        object_id: RelNode(
            id=object_id,
            kind=obj.kind,
            label=obj.name,
            role="self",
            depth=0,
            detail=obj.value or "",
        )
    }
    edges: list[RelEdge] = []
    for g, c, d in up:
        nodes.setdefault(
            g,
            RelNode(
                id=g,
                kind=info.get(g, ("", "group", None))[1],
                label=label(g),
                role="ancestor",
                depth=d,
            ),
        )
        edges.append(RelEdge(source=c, target=g, kind="member"))
    for g, c, d in down:
        nodes.setdefault(
            c,
            RelNode(
                id=c,
                kind=info.get(c, ("", "?", None))[1],
                label=label(c),
                role="descendant",
                depth=-d,
                detail=info.get(c, ("", "", None))[2] or "",
            ),
        )
        edges.append(RelEdge(source=c, target=g, kind="member"))

    # Rules using the object or any group above it, and through which level.
    via_ids = {object_id} | {g for g, _, _ in up}
    usage = db.execute(
        select(
            Rule.fmc_id,
            Rule.name,
            Rule.rule_index,
            Policy.name,
            RuleRef.field,
            RuleRef.object_fmc_id,
        )
        .join(RuleRef, RuleRef.rule_id == Rule.id)
        .join(
            Policy, (Policy.snapshot_id == Rule.snapshot_id) & (Policy.fmc_id == Rule.policy_fmc_id)
        )
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id.in_(via_ids))
        .order_by(Policy.name, Rule.rule_index)
        .limit(MAX_RULES * 4)
    ).all()
    by_rule: dict[str, dict[str, Any]] = {}
    for rid, rname, idx, pname, fld, via in usage:
        entry = by_rule.setdefault(
            rid, {"name": rname, "index": idx, "policy": pname, "fields": defaultdict(set)}
        )
        entry["fields"][fld].add(via)
    if len(by_rule) > MAX_RULES:
        truncated = True
    above = _reaches(up, object_id)
    issues: list[RelIssue] = []
    for rid, entry in list(by_rule.items())[:MAX_RULES]:
        node_id = f"rule:{rid}"
        deepest = max(nodes[v].depth for vs in entry["fields"].values() for v in vs if v in nodes)
        nodes[node_id] = RelNode(
            id=node_id,
            kind="rule",
            label=f"#{entry['index']} {entry['name']}",
            role="rule",
            depth=deepest + 1,
            detail=entry["policy"],
        )
        for fld, vias in entry["fields"].items():
            for via in vias:
                edges.append(RelEdge(source=via, target=node_id, kind="uses", label=fld))
            # Two references of one field where one is already inside the other.
            for inner in vias:
                outer = next((o for o in vias if o != inner and o in above.get(inner, set())), None)
                if outer is not None:
                    issues.append(
                        RelIssue(
                            kind="redundant_reference",
                            where_id=rid,
                            where_name=f"#{entry['index']} {entry['name']}",
                            removed=label(inner),
                            kept=label(outer),
                            recommendation_id=None,
                        )
                    )
    # Groups holding the object directly and again through a nested group.
    direct = {g for g, c, _ in up if c == object_id}
    for g in direct:
        nested = next(
            (
                c
                for gg, c, _ in up
                if gg == g and c != object_id and c in above.get(object_id, set())
            ),
            None,
        )
        if nested is not None:
            issues.append(
                RelIssue(
                    kind="redundant_member",
                    where_id=g,
                    where_name=label(g),
                    removed=obj.name,
                    kept=label(nested),
                    recommendation_id=None,
                )
            )

    # Link each issue to the recommendation that removes it (same snapshot). A rule that never
    # matches gets no reference clean-up: its removal is the fix.
    recs = db.execute(
        select(Recommendation.id, Recommendation.kind, Recommendation.targets).where(
            Recommendation.snapshot_id == snapshot_id,
            Recommendation.kind.in_(
                ("remove_redundant_reference", "remove_redundant_member", "remove_shadowed_rule")
            ),
        )
    ).all()
    by_target = {
        (kind.removeprefix("remove_"), str(t.get("id"))): rec_id
        for rec_id, kind, targets in recs
        for t in targets
    }
    for issue in issues:
        issue.recommendation_id = by_target.get((issue.kind, issue.where_id))
        if issue.recommendation_id is None and issue.kind == "redundant_reference":
            issue.recommendation_id = by_target.get(("shadowed_rule", issue.where_id))

    # Address objects overlapping the object (outside its own tree).
    own = {object_id} | {c for _, c, _ in down}
    leaves = [v for fid, (_, kind, v) in info.items() if v and kind in ADDRESS_KINDS and fid in own]
    if leaves:
        mine = AddressSet.build(leaves)
        found = 0
        for fid, name, kind, value in db.execute(
            select(FwObject.fmc_id, FwObject.name, FwObject.kind, FwObject.value)
            .where(
                FwObject.snapshot_id == snapshot_id,
                FwObject.kind.in_(ADDRESS_KINDS),
                FwObject.value.is_not(None),
            )
            .order_by(FwObject.name)
        ).all():
            if fid in nodes or value is None or found >= MAX_OVERLAPS:
                continue
            if value.endswith("/0"):
                continue  # "any" objects contain every address: no information
            other = AddressSet.build([value])
            if not mine.intersects(other):
                continue
            relation = (
                "same"
                if mine.covers(other) and other.covers(mine)
                else "contains"
                if mine.covers(other)
                else "within"
                if other.covers(mine)
                else "overlaps"
            )
            nodes[fid] = RelNode(
                id=fid, kind=kind, label=name, role="overlap", depth=0, detail=value
            )
            edges.append(RelEdge(source=object_id, target=fid, kind="overlap", label=relation))
            found += 1
        truncated = truncated or found >= MAX_OVERLAPS

    return Relations(
        object={"id": object_id, "name": obj.name, "kind": obj.kind, "value": obj.value},
        nodes=list(nodes.values()),
        edges=edges,
        issues=issues,
        truncated=truncated,
    )


# ------------------------------------------------------------------ lazy tree (explorer)


class TreeNode(BaseModel):
    id: str | None  # None for an inline literal member
    name: str
    kind: str
    value: str | None
    members: int  # direct members (groups)
    member_of: int  # groups holding it directly
    rule_refs: int  # rule fields referencing it directly
    read_only: bool


class TreePage(BaseModel):
    parent: str
    direction: str
    total: int
    offset: int
    nodes: list[TreeNode]


@router.get("/snapshots/{snapshot_id}/objects/{object_id}/tree", response_model=TreePage)
def object_tree(
    snapshot_id: int,
    object_id: FmcIdPath,
    db: DbDep,
    _: ReaderDep,
    direction: Annotated[str, Query(pattern="^(up|down)$")] = "down",
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> TreePage:
    """One level of the tree around an object, paged: its members (``down``) or the groups
    holding it (``up``), each with the counts needed to decide whether to expand further."""
    exists = db.scalar(
        select(FwObject.id).where(FwObject.snapshot_id == snapshot_id, FwObject.fmc_id == object_id)
    )
    if exists is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if direction == "down":
        link = select(
            GroupMember.member_fmc_id.label("oid"),
            GroupMember.member_name.label("name"),
            GroupMember.literal.label("literal"),
            GroupMember.id.label("pos"),
        ).where(GroupMember.snapshot_id == snapshot_id, GroupMember.group_fmc_id == object_id)
    else:
        link = select(
            GroupMember.group_fmc_id.label("oid"),
            literal("").label("name"),
            literal(None).label("literal"),
            GroupMember.id.label("pos"),
        ).where(GroupMember.snapshot_id == snapshot_id, GroupMember.member_fmc_id == object_id)
    rows = link.subquery()
    total = db.scalar(select(func.count()).select_from(rows)) or 0
    members = (
        select(func.count(GroupMember.id))
        .where(GroupMember.snapshot_id == snapshot_id, GroupMember.group_fmc_id == FwObject.fmc_id)
        .scalar_subquery()
    )
    member_of = (
        select(func.count(GroupMember.id))
        .where(GroupMember.snapshot_id == snapshot_id, GroupMember.member_fmc_id == FwObject.fmc_id)
        .scalar_subquery()
    )
    refs = (
        select(func.count(RuleRef.id))
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id == FwObject.fmc_id)
        .scalar_subquery()
    )
    query = (
        select(rows.c.oid, rows.c.name, rows.c.literal, FwObject, members, member_of, refs)
        .outerjoin(
            FwObject,
            (FwObject.snapshot_id == snapshot_id) & (FwObject.fmc_id == rows.c.oid),
        )
        .order_by(FwObject.name.nulls_last(), rows.c.pos)
        .offset(offset)
        .limit(limit)
    )
    nodes = []
    for oid, name, lit, obj, n_members, n_parents, n_refs in db.execute(query).all():
        if obj is None:
            nodes.append(
                TreeNode(
                    id=None if oid is None else str(oid),
                    name=str(lit or name or oid or "?"),
                    kind="literal" if oid is None else "unknown",
                    value=str(lit) if lit is not None else None,
                    members=0,
                    member_of=0,
                    rule_refs=0,
                    read_only=False,
                )
            )
            continue
        nodes.append(
            TreeNode(
                id=obj.fmc_id,
                name=obj.name,
                kind=obj.kind,
                value=obj.value,
                members=n_members or 0,
                member_of=n_parents or 0,
                rule_refs=n_refs or 0,
                read_only=bool((obj.attrs or {}).get("read_only")),
            )
        )
    return TreePage(parent=object_id, direction=direction, total=total, offset=offset, nodes=nodes)
