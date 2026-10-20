"""First-match shadowing and conflicting overlaps within one ordered policy.

* **Shadowed**: an earlier enabled, terminating rule matches *everything* a later rule
  matches, so the later rule can never be hit. Same action -> redundant; different
  action -> conflict (the later rule's intent is silently overridden).
* **Overlap conflict**: an earlier rule with the opposite verdict (permit vs deny)
  matches *part* of a later rule's traffic.

MONITOR rules log and continue evaluation, so they never shadow anything.

Scale: a naive pairwise scan is O(n^2) (~1 min for one 10K-rule policy). Rules are
anchored on their destination, so earlier rules are indexed by the smallest CIDR block
enclosing their IPv4 destination. CIDR blocks are either nested or disjoint, hence an
earlier rule can cover / intersect a later one only if its block encloses (ancestor) or
lies inside (descendant) the later rule's block: 33 dictionary lookups plus a sorted-key
range query per prefix level, instead of a scan. Sets without an IPv4 part fall back to a
full scan. ``analyse_order_naive`` is kept as the reference implementation for tests.
"""

from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import dataclass

from app.analysis.expand import RuleSpace
from app.analysis.space import AddressSet

NON_TERMINATING = frozenset({"MONITOR"})
DENY_ACTIONS = frozenset({"BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE"})
MAX_CONFLICTS_PER_RULE = 3


@dataclass(frozen=True)
class Shadow:
    rule: RuleSpace
    by: RuleSpace
    conflict: bool


@dataclass(frozen=True)
class Overlap:
    rule: RuleSpace
    with_rule: RuleSpace


def _verdict(action: str) -> str:
    return "deny" if action in DENY_ACTIONS else "permit"


def _block(addresses: AddressSet) -> tuple[int, int] | None:
    """(prefix length, block key) of the smallest IPv4 CIDR enclosing the set's IPv4 part."""
    bounds = addresses.v4_bounds()
    if bounds is None:
        return None
    lo, hi = bounds
    prefix = 32 - (lo ^ hi).bit_length()
    return prefix, lo >> (32 - prefix)


_ANY = (-1, 0)  # sentinel block for "any"


def _src_key(addresses: AddressSet) -> tuple[int, int] | None:
    """Source block for the integer pre-filter; ``_ANY`` for any, None if not IPv4-only."""
    if addresses.any:
        return _ANY
    return _block(addresses) if _pure_v4(addresses) else None


def _encloses(outer: tuple[int, int] | None, inner: tuple[int, int] | None) -> bool:
    """Necessary condition for coverage on the source dimension (cheap, integers only)."""
    if outer is None or inner is None:
        return True  # cannot decide cheaply: fall through to the exact check
    if outer == _ANY:
        return True
    if inner == _ANY:
        return False
    return outer[0] <= inner[0] and inner[1] >> (inner[0] - outer[0]) == outer[1]


def _nests(a: tuple[int, int] | None, b: tuple[int, int] | None) -> bool:
    """Necessary condition for intersection on the source dimension."""
    if a is None or b is None or a == _ANY or b == _ANY:
        return True
    return _encloses(a, b) or _encloses(b, a)


def _pure_v4(addresses: AddressSet) -> bool:
    return not addresses.any and bool(addresses.v4) and not addresses.v6 and not addresses.tokens


class _DestinationIndex:
    """Positions (evaluation order) of earlier terminating rules, by destination block."""

    def __init__(self) -> None:
        self.all: list[int] = []
        self.any: list[int] = []
        self.no_v4: list[int] = []  # concrete destinations without an IPv4 part
        self.mixed: list[int] = []  # IPv4 plus IPv6 / opaque tokens
        self.levels: list[dict[int, list[int]]] = [{} for _ in range(33)]
        self.keys: list[list[int]] = [[] for _ in range(33)]

    def add(self, pos: int, dst: AddressSet) -> None:
        self.all.append(pos)
        if dst.any:
            self.any.append(pos)
            return
        block = _block(dst)
        if block is None:
            self.no_v4.append(pos)
            return
        if not _pure_v4(dst):
            self.mixed.append(pos)
        prefix, key = block
        bucket = self.levels[prefix].setdefault(key, [])
        if not bucket:
            insort(self.keys[prefix], key)
        bucket.append(pos)

    def ancestors(self, prefix: int, key: int) -> list[int]:
        """Rules whose block encloses (or equals) the given block."""
        found: list[int] = []
        for p in range(prefix + 1):
            found.extend(self.levels[p].get(key >> (prefix - p), ()))
        return found

    def descendants(self, prefix: int, key: int) -> list[int]:
        """Rules whose block lies strictly inside the given block."""
        found: list[int] = []
        for p in range(prefix + 1, 33):
            shift = p - prefix
            lo, hi = key << shift, (key + 1) << shift
            keys = self.keys[p]
            i = bisect_left(keys, lo)
            while i < len(keys) and keys[i] < hi:
                found.extend(self.levels[p][keys[i]])
                i += 1
        return found

    def cover_candidates(self, dst: AddressSet) -> list[int]:
        if dst.any:
            return sorted(self.any)
        block = _block(dst)
        if block is None:
            return list(self.all)
        return sorted(set(self.any) | set(self.ancestors(*block)))

    def overlap_candidates(self, dst: AddressSet) -> list[int]:
        block = _block(dst)
        if dst.any or block is None or not _pure_v4(dst):
            return list(self.all)
        # A pure-IPv4 destination can only meet another rule's IPv4 part, whose block
        # then nests with ours; IPv6 / token parts of earlier rules cannot reach it.
        found = set(self.any) | set(self.ancestors(*block)) | set(self.descendants(*block))
        return sorted(found)


def analyse_order(rules: list[RuleSpace]) -> tuple[list[Shadow], list[Overlap]]:
    """``rules`` must be in evaluation order (one policy)."""
    shadows: list[Shadow] = []
    overlaps: list[Overlap] = []
    index = _DestinationIndex()
    by_pos: list[RuleSpace] = []
    src_keys: list[tuple[int, int] | None] = []
    for rule in rules:
        if not rule.enabled:
            continue
        b = rule.space
        b_src = _src_key(b.src_net)
        found: Shadow | None = None
        for pos in index.cover_candidates(b.dst_net):
            if not _encloses(src_keys[pos], b_src):
                continue
            earlier = by_pos[pos]
            if earlier.space.covers(b):
                found = Shadow(
                    rule=rule,
                    by=earlier,
                    conflict=_verdict(earlier.action) != _verdict(rule.action),
                )
                break
        if found is not None:
            shadows.append(found)  # a subset of an earlier rule adds no coverage: skip it
            continue
        conflicts = 0
        for pos in index.overlap_candidates(b.dst_net):
            if conflicts >= MAX_CONFLICTS_PER_RULE:
                break
            earlier = by_pos[pos]
            if (
                _verdict(earlier.action) != _verdict(rule.action)
                and _nests(src_keys[pos], b_src)
                and earlier.space.intersects(b)
            ):
                overlaps.append(Overlap(rule=rule, with_rule=earlier))
                conflicts += 1
        if rule.action not in NON_TERMINATING:
            index.add(len(by_pos), b.dst_net)
            by_pos.append(rule)
            src_keys.append(b_src)
    return shadows, overlaps


def analyse_order_naive(rules: list[RuleSpace]) -> tuple[list[Shadow], list[Overlap]]:
    """Reference O(n^2) implementation (tests compare the indexed version against it)."""
    shadows: list[Shadow] = []
    overlaps: list[Overlap] = []
    terminating: list[RuleSpace] = []
    for rule in rules:
        if not rule.enabled:
            continue
        found: Shadow | None = None
        for earlier in terminating:
            if earlier.space.covers(rule.space):
                found = Shadow(
                    rule=rule,
                    by=earlier,
                    conflict=_verdict(earlier.action) != _verdict(rule.action),
                )
                break
        if found is not None:
            shadows.append(found)
            continue
        conflicts = 0
        for earlier in terminating:
            if conflicts >= MAX_CONFLICTS_PER_RULE:
                break
            if _verdict(earlier.action) != _verdict(rule.action) and earlier.space.intersects(
                rule.space
            ):
                overlaps.append(Overlap(rule=rule, with_rule=earlier))
                conflicts += 1
        if rule.action not in NON_TERMINATING:
            terminating.append(rule)
    return shadows, overlaps
