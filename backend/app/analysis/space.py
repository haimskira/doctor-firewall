"""Match space of a rule: the exact set of traffic it can match, per dimension.

Used for shadowing ("an earlier rule matches everything this rule matches"), partial
overlap and size measures. Every operation is *conservative*: anything that cannot be
resolved to concrete addresses / ports (an FQDN, a stub object, an unknown token) is
kept as an opaque token that only covers itself, so the engine may miss a shadowed rule
but never reports one that is not.

* Addresses: merged, inclusive integer intervals, IPv4 and IPv6 kept apart.
* Ports: per-protocol integer intervals; protocol ``ALL`` covers every protocol.
* Everything else (zones, applications, URLs, SGTs, dynamic objects, users, VLANs):
  token sets.

An empty rule field means "any" and is represented with ``any=True``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

Interval = tuple[int, int]


def _merge(intervals: Iterable[Interval]) -> tuple[Interval, ...]:
    out: list[list[int]] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return tuple((lo, hi) for lo, hi in out)


def _covers(outer: tuple[Interval, ...], inner: tuple[Interval, ...]) -> bool:
    """Every inner interval is inside the union of (merged) outer intervals."""
    i = 0
    for lo, hi in inner:
        while i < len(outer) and outer[i][1] < lo:
            i += 1
        if i == len(outer) or outer[i][0] > lo or outer[i][1] < hi:
            return False
    return True


def _intersects(a: tuple[Interval, ...], b: tuple[Interval, ...]) -> bool:
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i][1] < b[j][0]:
            i += 1
        elif b[j][1] < a[i][0]:
            j += 1
        else:
            return True
    return False


def _intersection(a: tuple[Interval, ...], b: tuple[Interval, ...]) -> tuple[Interval, ...]:
    """The common part of two merged, sorted interval lists."""
    out: list[Interval] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tuple(out)


def _size(intervals: tuple[Interval, ...]) -> int:
    return sum(hi - lo + 1 for lo, hi in intervals)


@dataclass(frozen=True)
class AddressSet:
    any: bool = False
    v4: tuple[Interval, ...] = ()
    v6: tuple[Interval, ...] = ()
    tokens: frozenset[str] = frozenset()  # FQDNs and unresolvable objects

    @staticmethod
    def build(
        values: Iterable[str], tokens: Iterable[str] = (), *, any_: bool = False
    ) -> AddressSet:
        """``values`` are canonical ``a.b.c.d/n`` or ``start-end`` strings."""
        if any_:
            return AddressSet(any=True)
        v4: list[Interval] = []
        v6: list[Interval] = []
        for value in values:
            if "-" in value:
                start_text, _, end_text = value.partition("-")
                start, end = ipaddress.ip_address(start_text), ipaddress.ip_address(end_text)
                (v4 if start.version == 4 else v6).append((int(start), int(end)))
            else:
                net = ipaddress.ip_network(value, strict=False)
                target = v4 if net.version == 4 else v6
                target.append((int(net.network_address), int(net.broadcast_address)))
        return AddressSet(v4=_merge(v4), v6=_merge(v6), tokens=frozenset(tokens))

    def covers(self, other: AddressSet) -> bool:
        if self.any:
            return True
        if other.any:
            return False
        return (
            _covers(self.v4, other.v4)
            and _covers(self.v6, other.v6)
            and other.tokens <= self.tokens
        )

    def intersects(self, other: AddressSet) -> bool:
        if self.any or other.any:
            return True
        return (
            _intersects(self.v4, other.v4)
            or _intersects(self.v6, other.v6)
            or bool(self.tokens & other.tokens)
        )

    def intersection(self, other: AddressSet) -> AddressSet:
        """The addresses in both sets ("any" is the neutral element)."""
        if self.any:
            return other
        if other.any:
            return self
        return AddressSet(
            v4=_intersection(self.v4, other.v4),
            v6=_intersection(self.v6, other.v6),
            tokens=self.tokens & other.tokens,
        )

    @property
    def empty(self) -> bool:
        return not self.any and not self.v4 and not self.v6 and not self.tokens

    def size(self) -> int | None:
        """Number of addresses (None for "any"); opaque tokens count as one each."""
        if self.any:
            return None
        return _size(self.v4) + _size(self.v6) + len(self.tokens)

    def v4_bounds(self) -> Interval | None:
        if self.any or not self.v4:
            return None
        return self.v4[0][0], self.v4[-1][1]


ALL_PROTOCOLS = "ALL"


@dataclass(frozen=True)
class PortSet:
    any: bool = False
    by_protocol: tuple[tuple[str, tuple[Interval, ...]], ...] = ()
    tokens: frozenset[str] = frozenset()  # ICMP types and other non-port services

    @staticmethod
    def build(specs: Iterable[str], *, any_: bool = False) -> PortSet:
        """``specs`` are canonical ``PROTO/low-high`` / ``PROTO/n`` / ``PROTO/any`` strings."""
        if any_:
            return PortSet(any=True)
        ranges: dict[str, list[Interval]] = {}
        tokens: set[str] = set()
        for spec in specs:
            proto, _, ports = spec.partition("/")
            if proto in ("ICMP", "ICMPV6"):
                tokens.add(spec)
                continue
            if ports == "any" or not ports:
                ranges.setdefault(proto, []).append((0, 65535))
                continue
            low_text, sep, high_text = ports.partition("-")
            if not low_text.isdigit() or (sep and not high_text.isdigit()):
                tokens.add(spec)
                continue
            low = int(low_text)
            ranges.setdefault(proto, []).append((low, int(high_text) if sep else low))
        if (
            ALL_PROTOCOLS in ranges
            and ranges[ALL_PROTOCOLS]
            and _merge(ranges[ALL_PROTOCOLS]) == ((0, 65535),)
        ):
            return (
                PortSet(any=True)
                if not tokens
                else PortSet(
                    by_protocol=((ALL_PROTOCOLS, ((0, 65535),)),), tokens=frozenset(tokens)
                )
            )
        return PortSet(
            by_protocol=tuple(sorted((p, _merge(r)) for p, r in ranges.items())),
            tokens=frozenset(tokens),
        )

    def _ranges(self, proto: str) -> tuple[Interval, ...]:
        found = dict(self.by_protocol)
        return _merge(found.get(proto, ()) + found.get(ALL_PROTOCOLS, ()))

    def covers(self, other: PortSet) -> bool:
        if self.any:
            return True
        if other.any:
            return False
        all_full = _merge(dict(self.by_protocol).get(ALL_PROTOCOLS, ())) == ((0, 65535),)
        if not other.tokens <= self.tokens and not all_full:
            return False
        return all(_covers(self._ranges(proto), ranges) for proto, ranges in other.by_protocol)

    def intersects(self, other: PortSet) -> bool:
        if self.any or other.any:
            return True
        if self.tokens & other.tokens:
            return True
        protos = {p for p, _ in self.by_protocol} | {p for p, _ in other.by_protocol}
        return any(_intersects(self._ranges(p), other._ranges(p)) for p in protos)

    def port_count(self) -> int | None:
        if self.any:
            return None
        return sum(_size(r) for _, r in self.by_protocol) + len(self.tokens)


@dataclass(frozen=True)
class TokenSet:
    any: bool = False
    tokens: frozenset[str] = frozenset()

    @staticmethod
    def build(tokens: Iterable[str]) -> TokenSet:
        values = frozenset(tokens)
        return TokenSet(tokens=values) if values else TokenSet(any=True)

    def covers(self, other: TokenSet) -> bool:
        return self.any or (not other.any and other.tokens <= self.tokens)

    def intersects(self, other: TokenSet) -> bool:
        return self.any or other.any or bool(self.tokens & other.tokens)


TOKEN_DIMENSIONS = (
    "src_zone",
    "dst_zone",
    "app",
    "url",
    "src_sgt",
    "dst_sgt",
    "src_dyn",
    "dst_dyn",
    "user",
    "vlan",
)


@dataclass(frozen=True)
class MatchSpace:
    src_net: AddressSet = field(default_factory=lambda: AddressSet(any=True))
    dst_net: AddressSet = field(default_factory=lambda: AddressSet(any=True))
    src_port: PortSet = field(default_factory=lambda: PortSet(any=True))
    dst_port: PortSet = field(default_factory=lambda: PortSet(any=True))
    tokens: tuple[tuple[str, TokenSet], ...] = ()

    def token(self, dim: str) -> TokenSet:
        return dict(self.tokens).get(dim, TokenSet(any=True))

    def covers(self, other: MatchSpace) -> bool:
        return (
            self.dst_net.covers(other.dst_net)
            and self.src_net.covers(other.src_net)
            and self.dst_port.covers(other.dst_port)
            and self.src_port.covers(other.src_port)
            and all(self.token(d).covers(other.token(d)) for d in TOKEN_DIMENSIONS)
        )

    def intersects(self, other: MatchSpace) -> bool:
        return (
            self.dst_net.intersects(other.dst_net)
            and self.src_net.intersects(other.src_net)
            and self.dst_port.intersects(other.dst_port)
            and self.src_port.intersects(other.src_port)
            and all(self.token(d).intersects(other.token(d)) for d in TOKEN_DIMENSIONS)
        )
