"""Parse the output of ``show route`` (FTD / ASA, IPv4 global table) into routes.

The text comes from the device through the FMC and is treated as data: every field is
validated (addresses, masks, numbers, interface names), anything that does not parse is skipped
and counted, never interpreted. Format::

    S*       0.0.0.0 0.0.0.0 [1/0] via 10.0.0.1, outside
    C        10.1.1.0 255.255.255.0 is directly connected, inside
    L        10.1.1.1 255.255.255.255 is directly connected, inside
    B        10.50.0.0 255.255.0.0 [20/0] via 192.168.1.2, 2d03h
    O IA     10.60.0.0 255.255.255.0 [110/20] via 10.1.1.5, 1w2d, inside
                                     [110/20] via 10.1.1.6, 1w2d, inside     (equal-cost path)
    O E2     10.70.0.0 255.255.0.0
               [110/20] via 10.1.1.5, 00:10:01, inside                       (wrapped line)

BGP routes name no interface (the next hop is resolved recursively): the interface is taken
from the longest connected route covering the next hop.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Code letters (first column) -> protocol; the sub-type (IA, E1, EX, N2...) is kept as given.
PROTOCOLS = {
    "L": "local",
    "C": "connected",
    "S": "static",
    "R": "rip",
    "M": "mobile",
    "B": "bgp",
    "D": "eigrp",
    "O": "ospf",
    "i": "isis",
    "V": "vpn",
    "U": "user-static",
    "P": "periodic",
}
MAX_LINES = 200_000
_ROUTE = re.compile(
    r"^(?P<code>[A-Za-z])(?P<star>\*)?\s+(?:(?P<sub>[A-Z][A-Z0-9]?)\s+)?"
    r"(?P<net>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mask>\d{1,3}(?:\.\d{1,3}){3})(?P<rest>.*)$"
)
_VIA = re.compile(
    r"^\s*\[(?P<ad>\d{1,3})/(?P<metric>\d{1,10})\]\s+via\s+(?P<gw>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?P<tail>.*)$"
)
_CONNECTED = re.compile(r"^\s*is directly connected,\s*(?P<iface>[A-Za-z0-9_.:/-]{1,64})\s*$")
_IFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,63}$")
_AGE = re.compile(r"^(\d+[wdhms]\d*[wdhms]?\d*[wdhms]?|\d{1,2}:\d{2}:\d{2}|never)$")


@dataclass
class RuntimeRoute:
    code: str  # "B", "O", "S*" ...
    protocol: str  # bgp, ospf, ...
    subtype: str  # IA, E2, EX, ... or ""
    network: str  # canonical a.b.c.d/n
    distance: int | None
    metric: int | None
    gateway: str | None
    interface: str
    default_candidate: bool = False


@dataclass
class ParseResult:
    routes: list[RuntimeRoute] = field(default_factory=list)
    skipped: int = 0  # route-looking lines that did not parse


def _network(net: str, mask: str) -> str | None:
    try:
        return str(ipaddress.IPv4Network(f"{net}/{mask}", strict=True))
    except ValueError:
        return None


def _gateway(text: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def _via(text: str) -> tuple[int, int, str, str] | None:
    """``[ad/metric] via gw[, age][, iface]`` -> (ad, metric, gw, iface or "")."""
    m = _VIA.match(text)
    if m is None:
        return None
    gw = _gateway(m["gw"])
    if gw is None or int(m["ad"]) > 255:
        return None
    iface = ""
    for part in (p.strip() for p in m["tail"].split(",")):
        if not part or _AGE.match(part):
            continue
        if not _IFACE.match(part):
            return None
        iface = part
    return int(m["ad"]), int(m["metric"]), gw, iface


def parse(text: str) -> ParseResult:
    result = ParseResult()
    current: tuple[str, str, str, str, bool] | None = None  # code, protocol, sub, network, star
    for raw in text.splitlines()[:MAX_LINES]:
        line = raw.rstrip()
        if not line.strip():
            current = None
            continue
        head = _ROUTE.match(line)
        if head is not None:
            code = head["code"]
            protocol = PROTOCOLS.get(code)
            network = _network(head["net"], head["mask"])
            if protocol is None or network is None:
                result.skipped += 1
                current = None
                continue
            current = (code, protocol, head["sub"] or "", network, bool(head["star"]))
            rest = head["rest"]
            if not rest.strip():
                continue  # wrapped: the path follows on the next line
        elif current is not None and line[:1].isspace():
            rest = line  # another path of the current route (ECMP / wrapped line)
        else:
            if current is not None or line.lstrip()[:1] == "[":
                result.skipped += 1
            current = None
            continue
        code, protocol, sub, network, star = current
        connected = _CONNECTED.match(rest)
        if connected is not None:
            result.routes.append(
                RuntimeRoute(
                    code + ("*" if star else ""),
                    protocol,
                    sub,
                    network,
                    None,
                    None,
                    None,
                    connected["iface"],
                    star,
                )
            )
            continue
        via = _via(rest)
        if via is None:
            result.skipped += 1
            continue
        distance, metric, gateway, iface = via
        result.routes.append(
            RuntimeRoute(
                code + ("*" if star else ""),
                protocol,
                sub,
                network,
                distance,
                metric,
                gateway,
                iface,
                star,
            )
        )
    _resolve_interfaces(result.routes)
    return result


def _resolve_interfaces(routes: list[RuntimeRoute]) -> None:
    """Recursive next hops (BGP): the interface of the longest connected route covering them."""
    connected = sorted(
        (
            (ipaddress.IPv4Network(r.network), r.interface)
            for r in routes
            if r.protocol == "connected" and r.interface
        ),
        key=lambda item: item[0].prefixlen,
        reverse=True,
    )
    for r in routes:
        if r.interface or r.gateway is None:
            continue
        hop = ipaddress.IPv4Address(r.gateway)
        r.interface = next((iface for net, iface in connected if hop in net), "")
