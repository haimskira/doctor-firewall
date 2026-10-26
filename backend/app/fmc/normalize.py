"""Canonical forms for values found in FMC configuration.

Canonical values make semantically equal objects compare equal regardless of how
they were typed in the FMC (``10.20.5.7/24`` vs ``10.20.5.0/24``, netmask vs prefix,
protocol numbers vs names). Invalid input raises ``ValueError`` — FMC data is never
trusted to be well-formed.
"""

from __future__ import annotations

import ipaddress

_PROTOCOL_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPV6", "132": "SCTP"}
_KNOWN_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPV6", "SCTP", "GRE", "ESP", "AH", "ALL"}
MAX_TEXT = 1024


def host(value: str) -> str:
    """``10.0.0.1`` -> ``10.0.0.1/32`` (IPv6 -> /128).

    Some built-in FMC host objects carry a prefix (``any-ipv6`` is a Host with ``::/0``):
    those are kept as the network they describe.
    """
    if "/" in value:
        return network(value)
    addr = ipaddress.ip_address(value.strip())
    return f"{addr}/{addr.max_prefixlen}"


def network(value: str) -> str:
    """Canonical CIDR; host bits are cleared (FMC accepts ``10.0.0.7/24``)."""
    return str(ipaddress.ip_network(value.strip(), strict=False))


def address(value: str) -> str:
    """A host or a network literal, whichever it is."""
    text = value.strip()
    return network(text) if "/" in text else host(text)


def ip_range(value: str) -> str:
    start_text, sep, end_text = value.strip().partition("-")
    if not sep:
        raise ValueError("range must be <start>-<end>")
    start = ipaddress.ip_address(start_text.strip())
    end = ipaddress.ip_address(end_text.strip())
    if start.version != end.version or int(start) > int(end):
        raise ValueError("invalid address range")
    return f"{start}-{end}"


def prefix_length(netmask: str, version: int = 4) -> int:
    """Accept ``24`` or ``255.255.255.0``."""
    text = netmask.strip()
    if text.isdigit():
        length = int(text)
        if not 0 <= length <= (32 if version == 4 else 128):
            raise ValueError("invalid prefix length")
        return length
    return ipaddress.ip_network(f"0.0.0.0/{text}").prefixlen


def interface_cidr(address_text: str, netmask: str) -> str:
    """Interface address with its mask, e.g. ``10.1.0.1/16`` (host part kept)."""
    addr = ipaddress.ip_address(address_text.strip())
    return str(ipaddress.ip_interface(f"{addr}/{prefix_length(netmask, addr.version)}"))


def protocol(value: str | None) -> str:
    if value is None or not value.strip():
        return "ALL"
    text = value.strip().upper()
    text = _PROTOCOL_NAMES.get(text, text)
    if text not in _KNOWN_PROTOCOLS and not text.isdigit():
        raise ValueError("unknown protocol")
    return text


def port_spec(proto: str | None, port: str | None) -> str:
    """``TCP/443``, ``UDP/1000-2000``, ``TCP/any``."""
    p = protocol(proto)
    if port is None or not str(port).strip():
        return f"{p}/any"
    text = str(port).strip()
    low_text, sep, high_text = text.partition("-")
    low = int(low_text)
    high = int(high_text) if sep else low
    if not (0 <= low <= high <= 65535):
        raise ValueError("invalid port range")
    return f"{p}/{low}" if low == high else f"{p}/{low}-{high}"


def text(value: str | None, limit: int = MAX_TEXT) -> str:
    """Trimmed, length-bounded free text (FMC uses a single space for 'empty')."""
    cleaned = (value or "").strip()
    return cleaned[:limit]
