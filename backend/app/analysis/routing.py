"""Which route, interface and zone carry an address: longest-prefix match over the cluster's
connected, static and dynamic (runtime) routes, as the device itself decides."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    kind: str  # connected | static | dynamic
    protocol: str
    network: str
    interface: str
    gateway: str | None
    distance: int


def distance_of(kind: str, metric: int, distance: int | None) -> int:
    """Administrative distance: connected 0; static = its configured metric (FTD uses the
    static route metric as its distance); dynamic as reported by the device."""
    if kind == "connected":
        return 0
    if kind == "static":
        return metric or 1
    return distance if distance is not None else 255


def lookup(address: str, candidates: list[Candidate]) -> list[Candidate]:
    """Matching routes, best first: longest prefix, then lowest distance."""
    ip = ipaddress.IPv4Address(address)
    matches = [c for c in candidates if ip in ipaddress.IPv4Network(c.network)]
    return sorted(
        matches,
        key=lambda c: (-ipaddress.IPv4Network(c.network).prefixlen, c.distance, c.kind),
    )
