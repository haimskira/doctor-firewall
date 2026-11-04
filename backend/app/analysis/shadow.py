"""First-match shadowing and conflicting overlaps within one ordered policy.

* **Shadowed**: an earlier enabled, terminating rule matches *everything* a later rule
  matches, so the later rule can never be hit. Same action -> redundant; different
  action -> conflict (the later rule's intent is silently overridden).
* **Overlap conflict**: an earlier rule with the opposite verdict (permit vs deny)
  matches *part* of a later rule's traffic.

MONITOR rules log and continue evaluation, so they never shadow anything. A rule with match
conditions the space model does not represent never shadows another one (see
:class:`app.analysis.space.MatchSpace`).

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
from collections.abc import Iterable
from dataclasses import dataclass
from heapq import merge

from app.analysis.expand import RuleSpace
from app.analysis.space import AddressSet

NON_TERMINATING = frozenset({"MONITOR"})
DENY_ACTIONS = frozenset({"BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE"})
# Prefilter outcomes that let traffic through differently: FASTPATH bypasses inspection,
# ANALYZE hands it on to the access policy. They are neither "permit" nor each other.
DISTINCT_VERDICTS = frozenset({"FASTPATH", "ANALYZE"})
MAX_CONFLICTS_PER_RULE = 3
# Earlier rules examined per rule for overlap conflicts (findings only; shadowing is exact).
# Without it a policy of tens of thousands of "any" / IPv6 / token destinations is O(n^2).
MAX_OVERLAP_SCAN = 4000
MAX_ANY_DESTINATIONS = 64


@dataclass(frozen=True)
class Shadow:
    rule: RuleSpace
    by: RuleSpace
    conflict: bool


@dataclass(frozen=True)
class Overlap:
    rule: RuleSpace
    with_rule: RuleSpace


def verdict(action: str) -> str:
    """What a rule does with the traffic it matches, for "same intent" comparisons: every
    BLOCK variant denies, prefilter FASTPATH and ANALYZE are outcomes of their own, anything
    else permits."""
    if action in DENY_ACTIONS:
        return "deny"
    if action in DISTINCT_VERDICTS:
        return action.lower()
    return "permit"


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
        self.by_verdict: dict[str, list[int]] = {}
        self.any: list[int] = []
        self.no_v4: list[int] = []  # concrete destinations without an IPv4 part
        self.mixed: list[int] = []  # IPv4 plus IPv6 / opaque tokens
        self.levels: list[dict[int, list[int]]] = [{} for _ in range(33)]
        self.keys: list[list[int]] = [[] for _ in range(33)]

    def add(self, pos: int, dst: AddressSet, outcome: str) -> None:
        self.all.append(pos)
        self.by_verdict.setdefault(outcome, []).append(pos)
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
            if dst.empty:
                return self.all
            # Without an IPv4 part the set has IPv6 / tokens: an earlier rule covering it must
            # have such a part too, so a pure-IPv4 set never qualifies.
            return sorted(self.any + self.no_v4 + self.mixed)
        # Disjoint lists (each position is indexed once): no set needed to deduplicate.
        return sorted(self.any + self.ancestors(*block))

    def overlap_candidates(self, dst: AddressSet, outcome: str) -> Iterable[int]:
        block = _block(dst)
        if dst.any or block is None or not _pure_v4(dst):
            # Lazy, evaluation order, only earlier rules with the opposite verdict.
            return merge(*(v for k, v in self.by_verdict.items() if k != outcome))
        # A pure-IPv4 destination can only meet another rule's IPv4 part, whose block
        # then nests with ours; IPv6 / token parts of earlier rules cannot reach it.
        return sorted(self.any + self.ancestors(*block) + self.descendants(*block))


def analyse_order(rules: list[RuleSpace]) -> tuple[list[Shadow], list[Overlap]]:
    """``rules`` must be in evaluation order (one policy)."""
    shadows: list[Shadow] = []
    overlaps: list[Overlap] = []
    index = _DestinationIndex()
    # Cover candidates: any-destination rules are looked up by source, the others by destination.
    any_by_source = _DestinationIndex()
    concrete = _DestinationIndex()
    all_by_source = _DestinationIndex()
    by_source: dict[str, _DestinationIndex] = {}  # earlier rules by verdict, indexed on source
    by_pos: list[RuleSpace] = []
    src_keys: list[tuple[int, int] | None] = []
    for rule in rules:
        if not rule.enabled:
            continue
        b = rule.space
        b_src = _src_key(b.src_net)
        found: Shadow | None = None
        if b.src_net.any or (_block(b.src_net) is not None and _pure_v4(b.src_net)):
            # Whoever covers the rule covers its source: a short list when sources are concrete.
            cover = all_by_source.cover_candidates(b.src_net)
        elif b.dst_net.any:
            cover = any_by_source.cover_candidates(b.src_net)
        else:
            cover = list(
                merge(
                    concrete.cover_candidates(b.dst_net),
                    any_by_source.cover_candidates(b.src_net),
                )
            )
        for pos in cover:
            if not _encloses(src_keys[pos], b_src):
                continue
            earlier = by_pos[pos]
            if earlier.space.covers(b):
                found = Shadow(
                    rule=rule,
                    by=earlier,
                    conflict=verdict(earlier.action) != verdict(rule.action),
                )
                break
        if found is not None:
            shadows.append(found)  # a subset of an earlier rule adds no coverage: skip it
            continue
        conflicts = 0
        mine = verdict(rule.action)
        if (
            _block(b.dst_net) is not None
            and _pure_v4(b.dst_net)
            and len(index.any) <= MAX_ANY_DESTINATIONS  # else they would flood the list
        ):
            candidates: Iterable[int] = index.overlap_candidates(b.dst_net, mine)
        else:
            # No IPv4-only destination to anchor on: anchor on the source instead, per verdict.
            candidates = merge(
                *(
                    idx.overlap_candidates(b.src_net, mine)
                    for k, idx in by_source.items()
                    if k != mine
                )
            )
        for scanned, pos in enumerate(candidates):
            if conflicts >= MAX_CONFLICTS_PER_RULE or scanned >= MAX_OVERLAP_SCAN:
                break
            earlier = by_pos[pos]
            if (
                verdict(earlier.action) != mine
                and _nests(src_keys[pos], b_src)
                and earlier.space.intersects(b)
            ):
                overlaps.append(Overlap(rule=rule, with_rule=earlier))
                conflicts += 1
        if rule.action not in NON_TERMINATING:
            index.add(len(by_pos), b.dst_net, mine)
            if b.dst_net.any:
                any_by_source.add(len(by_pos), b.src_net, mine)
            else:
                concrete.add(len(by_pos), b.dst_net, mine)
            all_by_source.add(len(by_pos), b.src_net, mine)
            by_source.setdefault(mine, _DestinationIndex()).add(len(by_pos), b.src_net, mine)
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
                    conflict=verdict(earlier.action) != verdict(rule.action),
                )
                break
        if found is not None:
            shadows.append(found)
            continue
        conflicts = 0
        for earlier in terminating:
            if conflicts >= MAX_CONFLICTS_PER_RULE:
                break
            if verdict(earlier.action) != verdict(rule.action) and earlier.space.intersects(
                rule.space
            ):
                overlaps.append(Overlap(rule=rule, with_rule=earlier))
                conflicts += 1
        if rule.action not in NON_TERMINATING:
            terminating.append(rule)
    return shadows, overlaps
