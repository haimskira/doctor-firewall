"""``show route`` output as an FTD prints it, generated from the mock's device configuration.

Connected / local routes come from the interfaces, static ones from the static routes; a few
dynamic routes (BGP via the outside peer, OSPF with two equal-cost paths and a wrapped line,
EIGRP) are added so the collector sees every format it must parse.
"""

from __future__ import annotations

import ipaddress
from typing import Any

HEADER = """Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2, V - VPN
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       o - ODR, P - periodic downloaded static route, + - replicated route
       SI - Static InterVRF, BI - BGP InterVRF
"""


def _mask(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _net(network: ipaddress.IPv4Network) -> str:
    return f"{network.network_address} {network.netmask}"


def show_route(
    interfaces: dict[str, list[dict[str, Any]]],
    static: list[dict[str, Any]],
    objects: dict[str, dict[str, Any]],
) -> str:
    lines: list[str] = []
    connected: list[tuple[ipaddress.IPv4Interface, str]] = []
    for items in interfaces.values():
        for item in items:
            ipv4 = ((item.get("ipv4") or {}).get("static")) or {}
            if not item.get("ifname") or not ipv4.get("address"):
                continue
            mask = str(ipv4.get("netmask", "32"))
            prefix = (
                mask if mask.isdigit() else str(ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen)
            )
            connected.append(
                (ipaddress.IPv4Interface(f"{ipv4['address']}/{prefix}"), item["ifname"])
            )
    outside = next((i for i, n in connected if n == "outside"), None)
    cluster = int(str(outside.ip).rsplit(".", 1)[1]) if outside is not None else 1
    outside_gw = None
    for route in static:
        gateway = route.get("gateway") or {}
        literal = (gateway.get("literal") or {}).get("value")
        obj = objects.get(((gateway.get("object") or {}).get("id")) or "")
        hop = literal or (obj or {}).get("value")
        if hop is None:
            continue
        for ref in route.get("selectedNetworks", []):
            value = (objects.get(ref.get("id", "")) or {}).get("value")
            if value is None:
                continue
            network = ipaddress.IPv4Network(value if "/" in value else f"{value}/32", strict=False)
            star = "*" if network.prefixlen == 0 else " "
            if network.prefixlen == 0:
                outside_gw = hop
            lines.append(f"S{star}       {_net(network)} [1/0] via {hop}, {route['interfaceName']}")
    for iface, name in connected:
        lines.append(f"C        {_net(iface.network)} is directly connected, {name}")
        lines.append(f"L        {iface.ip} 255.255.255.255 is directly connected, {name}")
    inside = next((i for i, n in connected if n == "inside"), None)
    dc = next((i for i, n in connected if n == "dc"), None)
    if outside_gw is not None:
        lines.append(f"B        10.50.0.0 255.255.0.0 [20/0] via {outside_gw}, 2d03h")
        lines.append(f"B        198.51.{cluster}.0 255.255.255.0 [20/0] via {outside_gw}, 2d03h")
    if inside is not None:
        base = inside.network.network_address
        lines.append(
            f"O IA     10.60.{cluster}.0 255.255.255.0 [110/20] via {base + 2}, 1w2d, inside"
        )
        lines.append(f"                                 [110/20] via {base + 3}, 1w2d, inside")
        lines.append(f"O E2     10.70.{cluster}.0 {_mask(24)}")
        lines.append(f"           [110/20] via {base + 2}, 00:10:01, inside")
    if dc is not None:
        lines.append(
            f"D EX     10.80.{cluster}.0 255.255.255.0 [170/2816] via "
            f"{dc.network.network_address + 5}, 00:10:01, dc"
        )
    last_resort = (
        f"Gateway of last resort is {outside_gw} to network 0.0.0.0"
        if outside_gw
        else "Gateway of last resort is not set"
    )
    return HEADER + "\n" + last_resort + "\n\n" + "\n".join(lines) + "\n"
