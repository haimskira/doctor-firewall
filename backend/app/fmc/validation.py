"""Validation of values that identify or come from the FMC."""

from __future__ import annotations

import ipaddress
import re

_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# FMC tokens are UUID-like; accept a conservative superset and nothing else.
TOKEN_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")


def validate_host(value: str) -> str:
    """Accept a DNS hostname or a bare IPv4/IPv6 literal (no scheme, port, path or userinfo)."""
    host = value.strip()
    if not host or len(host) > 253:
        raise ValueError("invalid host")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    if not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid host")
    return host.lower()


def host_for_url(host: str) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host
