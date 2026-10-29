"""Changeset composition: conflicts between plans, safe order, batches under the deploy limit.

Rules (docs/enforcement.md):

* Every recommendation is applied atomically inside one batch — a split rule is never left
  half-done between two deploys. A recommendation larger than the limit cannot be batched.
* Two recommendations conflict if they modify the same rule or object, or if one deletes
  something the other modifies or references. Conflicts are reported, never resolved silently.
* Order: object creations and reference rewrites before rule changes, renames, then
  deletions (rules before objects), so an object is only deleted after its users moved.
* A batch's limit is the smallest deploy limit of the clusters it affects; it is recomputed
  as items are added (adding a cluster may lower it).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.enforce.plan import touched

KIND_ORDER = (
    "literal_to_object",
    "split_group",
    "merge_groups",
    "merge_duplicate_objects",
    "remove_redundant_member",
    "remove_redundant_reference",
    "split_rule",
    "merge_rules",
    "tighten_source",
    "tighten_ports",
    "add_inspection",
    "rename_role",
    "rename_convention",
    "remove_shadowed_rule",
    "remove_dead_rule",
    "remove_unused_object",
)


@dataclass(frozen=True)
class Item:
    key: str  # recommendation fingerprint
    kind: str
    title: str
    plan: dict[str, object]
    clusters: frozenset[str]

    @property
    def op_count(self) -> int:
        ops = self.plan.get("ops", [])
        return len(ops) if isinstance(ops, list) else 0


@dataclass(frozen=True)
class Conflict:
    first: str
    second: str
    reason: str  # same_rule | same_object | deletes_used


@dataclass
class PlannedBatch:
    seq: int
    items: list[Item] = field(default_factory=list)
    clusters: set[str] = field(default_factory=set)
    limit: int = 0

    @property
    def op_count(self) -> int:
        return sum(i.op_count for i in self.items)


class ItemTooLargeError(ValueError):
    def __init__(self, item: Item, limit: int) -> None:
        super().__init__(f"{item.key}: {item.op_count} operations > limit {limit}")
        self.item = item
        self.limit = limit


def _clash(t: dict[str, set[str]], o: dict[str, set[str]]) -> str | None:
    if t["rules"] & o["rules"]:
        return "same_rule"
    if t["objects"] & o["objects"]:
        return "same_object"
    if (t["deleted"] & (o["referenced"] | o["objects"] | o["rules"])) or (
        o["deleted"] & (t["referenced"] | t["objects"] | t["rules"])
    ):
        return "deletes_used"
    return None


def conflicts(items: Iterable[Item]) -> list[Conflict]:
    seen: list[tuple[Item, dict[str, set[str]]]] = []
    found: list[Conflict] = []
    for item in items:
        t = touched(item.plan)
        for other, o in seen:
            reason = _clash(t, o)
            if reason is not None:
                found.append(Conflict(other.key, item.key, reason))
        seen.append((item, t))
    return found


def separate(items: Iterable[Item]) -> tuple[list[Item], list[Conflict]]:
    """The items one changeset can take, and those held back: in order, an item touching what an
    item already taken touches waits (``Conflict(taken, held, reason)``) for a later changeset,
    staged from the snapshot after this one is deployed (its plan is built on that state)."""
    taken: list[tuple[Item, dict[str, set[str]]]] = []
    held: list[Conflict] = []
    for item in items:
        t = touched(item.plan)
        clash = next(((other, r) for other, o in taken if (r := _clash(t, o)) is not None), None)
        if clash is None:
            taken.append((item, t))
        else:
            held.append(Conflict(clash[0].key, item.key, clash[1]))
    return [i for i, _ in taken], held


def order(items: Iterable[Item]) -> list[Item]:
    rank = {k: i for i, k in enumerate(KIND_ORDER)}
    return sorted(items, key=lambda i: (rank.get(i.kind, len(KIND_ORDER)), i.key))


def batch(items: Iterable[Item], limit_of: Callable[[set[str]], int]) -> list[PlannedBatch]:
    """Greedy packing in safe order; ``limit_of(clusters)`` is the deploy limit for a set."""
    batches: list[PlannedBatch] = []
    current = PlannedBatch(seq=1)
    for item in order(items):
        alone = limit_of(set(item.clusters))
        if item.op_count > alone:
            raise ItemTooLargeError(item, alone)
        merged = current.clusters | item.clusters
        limit = limit_of(merged)
        if current.items and current.op_count + item.op_count > limit:
            batches.append(current)
            current = PlannedBatch(seq=current.seq + 1)
            merged = set(item.clusters)
            limit = alone
        current.items.append(item)
        current.clusters = merged
        current.limit = limit
    if current.items:
        batches.append(current)
    return batches
