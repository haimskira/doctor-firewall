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

from fastapi import APIRouter, Depends, HTTPException, Path, status
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

    # Link each issue to the recommendation that removes it (same snapshot).
    recs = db.execute(
        select(Recommendation.id, Recommendation.kind, Recommendation.targets).where(
            Recommendation.snapshot_id == snapshot_id,
            Recommendation.kind.in_(("remove_redundant_reference", "remove_redundant_member")),
        )
    ).all()
    by_target = {
        (kind.removeprefix("remove_"), str(t.get("id"))): rec_id
        for rec_id, kind, targets in recs
        for t in targets
    }
    for issue in issues:
        issue.recommendation_id = by_target.get((issue.kind, issue.where_id))

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
