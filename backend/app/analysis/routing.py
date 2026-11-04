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


def _network(text: str) -> ipaddress.IPv4Network | None:
    """The route's network, or None when it is not one (a range "a-b", an FQDN, IPv6):
    such a route cannot carry an IPv4 address by prefix match."""
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    return net if isinstance(net, ipaddress.IPv4Network) else None


def lookup(address: str, candidates: list[Candidate]) -> list[Candidate]:
    """Matching routes, best first: longest prefix, then lowest distance. Candidates whose
    network does not parse as an IPv4 network are skipped."""
    ip = ipaddress.IPv4Address(address)
    matches: list[tuple[int, Candidate]] = []
    for c in candidates:
        net = _network(c.network)
        if net is not None and ip in net:
            matches.append((net.prefixlen, c))
    matches.sort(key=lambda m: (-m[0], m[1].distance, m[1].kind))
    return [c for _, c in matches]
