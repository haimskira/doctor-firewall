"""``show route`` parsing and longest-prefix lookup."""

from __future__ import annotations

from app.analysis.routing import Candidate, distance_of, lookup
from app.fmc.showroute import parse

OUTPUT = """Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       E1 - OSPF external type 1, E2 - OSPF external type 2, V - VPN

Gateway of last resort is 203.0.113.254 to network 0.0.0.0

S*       0.0.0.0 0.0.0.0 [1/0] via 203.0.113.254, outside
C        203.0.113.0 255.255.255.0 is directly connected, outside
L        203.0.113.1 255.255.255.255 is directly connected, outside
C        10.1.0.0 255.255.0.0 is directly connected, inside
B        10.50.0.0 255.255.0.0 [20/0] via 203.0.113.254, 2d03h
O IA     10.60.1.0 255.255.255.0 [110/20] via 10.1.0.2, 1w2d, inside
                                 [110/20] via 10.1.0.3, 1w2d, inside
O E2     10.70.1.0 255.255.255.0
           [110/20] via 10.1.0.2, 00:10:01, inside
D EX     10.80.1.0 255.255.255.0 [170/2816] via 10.1.0.5, 00:10:01, inside
B        10.90.0.0 255.255.0.0 [20/0] via 192.0.2.9, 2d03h
O        10.99.0.1 255.255.0.0 [110/20] via 10.1.0.2, 1w2d, inside
B        10.91.0.0 255.255.0.0 [20/0] via 10.1.0.300, 2d03h
B        10.92.0.0 255.255.0.0 [20/0] via 10.1.0.9, 2d03h, in$ide
"""


def test_formats_wrapped_lines_ecmp_and_recursive_next_hops() -> None:
    result = parse(OUTPUT)
    by = {(r.network, r.gateway): r for r in result.routes}
    default = by[("0.0.0.0/0", "203.0.113.254")]
    assert (default.code, default.protocol, default.default_candidate) == ("S*", "static", True)
    assert by[("10.1.0.0/16", None)].interface == "inside"
    bgp = by[("10.50.0.0/16", "203.0.113.254")]
    # BGP names no interface: resolved through the connected route covering the next hop.
    assert (bgp.protocol, bgp.distance, bgp.interface) == ("bgp", 20, "outside")
    ecmp = [r for r in result.routes if r.network == "10.60.1.0/24"]
    assert [(r.subtype, r.gateway) for r in ecmp] == [("IA", "10.1.0.2"), ("IA", "10.1.0.3")]
    wrapped = by[("10.70.1.0/24", "10.1.0.2")]
    assert (wrapped.protocol, wrapped.subtype, wrapped.metric) == ("ospf", "E2", 20)
    eigrp = by[("10.80.1.0/24", "10.1.0.5")]
    assert (eigrp.protocol, eigrp.subtype, eigrp.distance) == ("eigrp", "EX", 170)
    # A next hop no connected route covers: no interface rather than a guess.
    assert by[("10.90.0.0/16", "192.0.2.9")].interface == ""
    # Host bits in the network, an invalid next hop, a malformed interface: skipped, counted.
    networks = {r.network for r in result.routes}
    assert not networks & {"10.99.0.1/16", "10.99.0.0/16", "10.91.0.0/16", "10.92.0.0/16"}
    assert result.skipped == 3


def test_garbage_is_data_not_commands() -> None:
    result = parse("rm -rf /\n; reboot\nX 10.0.0.0 255.0.0.0 [1/0] via 10.0.0.1, inside\n")
    assert result.routes == []
    assert result.skipped == 1  # unknown protocol code


def test_longest_prefix_then_distance() -> None:
    routes = [
        Candidate("static", "static", "0.0.0.0/0", "outside", "203.0.113.254", 1),
        Candidate("connected", "connected", "10.1.0.0/16", "inside", None, 0),
        Candidate("dynamic", "ospf", "10.1.5.0/24", "inside", "10.1.0.2", 110),
        Candidate("dynamic", "bgp", "10.1.5.0/24", "outside", "203.0.113.254", 20),
    ]
    best = lookup("10.1.5.9", routes)
    assert [(m.protocol, m.network) for m in best] == [
        ("bgp", "10.1.5.0/24"),
        ("ospf", "10.1.5.0/24"),
        ("connected", "10.1.0.0/16"),
        ("static", "0.0.0.0/0"),
    ]
    assert lookup("8.8.8.8", routes)[0].network == "0.0.0.0/0"
    assert distance_of("connected", 5, None) == 0
    assert distance_of("static", 10, None) == 10
    assert distance_of("dynamic", 0, None) == 255
