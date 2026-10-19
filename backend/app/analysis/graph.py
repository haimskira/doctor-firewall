"""Object-group graph algorithms (pure; no database access).

Nodes are group FMC ids; a group's members are other groups, plain objects, or
literals. Real FMCs reject cyclic groups, but a local copy must never hang or
recurse forever on one, so every traversal is cycle-safe.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

Leaf = str  # object fmc id, or "lit:<value>" for an inline literal


@dataclass
class GroupGraph:
    members: dict[str, list[str]] = field(default_factory=dict)  # group -> member ids/literals

    def is_group(self, node: str) -> bool:
        return node in self.members

    def child_groups(self, group: str) -> list[str]:
        return [m for m in self.members.get(group, []) if self.is_group(m)]


def strongly_connected(graph: GroupGraph) -> list[list[str]]:
    """Tarjan's algorithm (iterative). Returns cycles: SCCs of size > 1 or self-loops."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []
    counter = 0
    for root in graph.members:
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, child_i = work.pop()
            if child_i == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            children = graph.child_groups(node)
            if child_i < len(children):
                work.append((node, child_i + 1))
                child = children[child_i]
                if child not in index:
                    work.append((child, 0))
                elif child in on_stack:
                    low[node] = min(low[node], index[child])
                continue
            if low[node] == index[node]:
                component = []
                while True:
                    top = stack.pop()
                    on_stack.discard(top)
                    component.append(top)
                    if top == node:
                        break
                if len(component) > 1 or node in graph.child_groups(node):
                    cycles.append(sorted(component))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return cycles


def depths(graph: GroupGraph, cyclic: set[str]) -> dict[str, int]:
    """Nesting depth (a group of plain objects has depth 1). Cyclic groups are skipped."""
    result: dict[str, int] = {}
    for root in graph.members:
        if root in cyclic or root in result:
            continue
        work: list[tuple[str, bool]] = [(root, False)]
        while work:
            node, expanded = work.pop()
            if node in result:
                continue
            children = [c for c in graph.child_groups(node) if c not in cyclic]
            if expanded:
                result[node] = 1 + max((result[c] for c in children), default=0)
                continue
            work.append((node, True))
            work.extend((c, False) for c in children if c not in result)
    return result


def leaf_counts(graph: GroupGraph, cyclic: set[str]) -> dict[str, Counter[Leaf]]:
    """For every acyclic group: how many distinct paths reach each leaf."""
    order = depths(graph, cyclic)
    result: dict[str, Counter[Leaf]] = {}
    for group in sorted(order, key=order.__getitem__):  # children before parents
        counts: Counter[Leaf] = Counter()
        for member in graph.members[group]:
            if graph.is_group(member):
                if member in result:
                    counts.update(result[member])
            else:
                counts[member] += 1
        result[group] = counts
    return result


def introduced_duplicates(counts: Counter[Leaf], parts: Iterable[Counter[Leaf]]) -> dict[Leaf, int]:
    """Leaves duplicated in ``counts`` that are not already duplicated inside one part.

    This reports a duplicate where it is introduced, not again in every ancestor.
    """
    inherited: set[Leaf] = set()
    for part in parts:
        inherited.update(leaf for leaf, n in part.items() if n > 1)
    return {leaf: n for leaf, n in counts.items() if n > 1 and leaf not in inherited}


def combine(
    refs: Iterable[str], graph: GroupGraph, counts: Mapping[str, Counter[Leaf]]
) -> tuple[Counter[Leaf], list[Counter[Leaf]]]:
    """Leaf multiset of a list of references (e.g. one rule field) plus its parts."""
    total: Counter[Leaf] = Counter()
    parts: list[Counter[Leaf]] = []
    for ref in refs:
        part = counts.get(ref) if graph.is_group(ref) else Counter({ref: 1})
        if part is None:  # cyclic group: no well-defined leaf set
            continue
        parts.append(part)
        total.update(part)
    return total, parts
