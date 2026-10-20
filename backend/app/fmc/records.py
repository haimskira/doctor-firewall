"""Version-neutral records produced by the FMC adapters and stored in snapshots.

The analysis engine and the API only ever see these shapes; FMC JSON stays inside
``app/fmc/adapters``. Supporting a new FMC version means a new adapter, nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ObjectKind(StrEnum):
    HOST = "host"
    NETWORK = "network"
    RANGE = "range"
    FQDN = "fqdn"
    NETWORK_GROUP = "network_group"
    PORT = "port"
    PORT_GROUP = "port_group"
    ICMP = "icmp"
    ZONE = "zone"
    SGT = "sgt"
    DYNAMIC = "dynamic"
    APPLICATION = "application"
    URL = "url"
    URL_GROUP = "url_group"
    GEO = "geo"
    OTHER = "other"


GROUP_KINDS = frozenset({ObjectKind.NETWORK_GROUP, ObjectKind.PORT_GROUP, ObjectKind.URL_GROUP})


class PolicyKind(StrEnum):
    """Policies collected per snapshot. The first five carry rules."""

    ACCESS = "access"
    PREFILTER = "prefilter"
    DECRYPTION = "decryption"
    IDENTITY = "identity"
    NAT = "nat"
    INTRUSION = "intrusion"
    FILE = "file"
    DNS = "dns"


RULE_POLICY_KINDS = frozenset(
    {
        PolicyKind.ACCESS,
        PolicyKind.PREFILTER,
        PolicyKind.DECRYPTION,
        PolicyKind.IDENTITY,
        PolicyKind.NAT,
    }
)


class RuleField(StrEnum):
    SRC_ZONE = "src_zone"
    DST_ZONE = "dst_zone"
    SRC_NET = "src_net"
    DST_NET = "dst_net"
    SRC_PORT = "src_port"
    DST_PORT = "dst_port"
    APP = "app"
    URL = "url"
    SRC_SGT = "src_sgt"
    DST_SGT = "dst_sgt"
    SRC_DYN = "src_dyn"
    DST_DYN = "dst_dyn"
    USER = "user"
    VLAN = "vlan"
    # NAT: original (pre-translation) and translated values.
    NAT_ORIG_SRC = "nat_orig_src"
    NAT_TRANS_SRC = "nat_trans_src"
    NAT_ORIG_DST = "nat_orig_dst"
    NAT_TRANS_DST = "nat_trans_dst"
    NAT_ORIG_SPORT = "nat_orig_sport"
    NAT_TRANS_SPORT = "nat_trans_sport"
    NAT_ORIG_DPORT = "nat_orig_dport"
    NAT_TRANS_DPORT = "nat_trans_dport"


@dataclass(frozen=True)
class Ref:
    """A reference to an FMC object (``object_id``) or an inline literal value."""

    object_id: str | None = None
    name: str = ""
    fmc_type: str = ""
    literal: str | None = None
    literal_kind: str | None = None


@dataclass(frozen=True)
class ObjectRecord:
    fmc_id: str
    kind: ObjectKind
    fmc_type: str
    name: str
    value: str | None
    attrs: dict[str, Any] = field(default_factory=dict)
    members: tuple[Ref, ...] = ()  # for groups


@dataclass(frozen=True)
class RuleRecord:
    fmc_id: str
    rule_index: int
    section: str
    category: str
    name: str
    enabled: bool
    action: str
    ips_policy: str | None
    file_policy: str | None
    variable_set: str | None
    log_begin: bool
    log_end: bool
    send_events: bool
    attrs: dict[str, Any]
    refs: tuple[tuple[RuleField, Ref], ...]
    # PREFILTER / TUNNEL (prefilter), AUTO / MANUAL (NAT); None for other kinds.
    rule_type: str | None = None
    # Referenced intrusion / file policy ids (links into the policy inventory).
    ips_policy_id: str | None = None
    file_policy_id: str | None = None


@dataclass(frozen=True)
class DeviceRecord:
    fmc_id: str
    name: str
    model: str
    sw_version: str
    policy_id: str | None


@dataclass(frozen=True)
class HaPairRecord:
    fmc_id: str
    name: str
    primary_id: str
    secondary_id: str


@dataclass(frozen=True)
class AssignmentRecord:
    policy_id: str
    target_ids: tuple[str, ...]
    policy_type: str = "AccessPolicy"


@dataclass(frozen=True)
class PolicyRecord:
    fmc_id: str
    name: str
    default_action: str
    kind: PolicyKind = PolicyKind.ACCESS
    # Policies this one references, e.g. ("prefilterPolicySetting", Ref(...)).
    links: tuple[tuple[str, Ref], ...] = ()
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HitCountRecord:
    rule_id: str
    hit_count: int
    last_hit: str | None


@dataclass(frozen=True)
class InterfaceRecord:
    fmc_id: str
    kind: str
    name: str
    ifname: str
    enabled: bool
    zone_id: str | None
    ipv4: str | None
    vlan: int | None


@dataclass(frozen=True)
class StaticRouteRecord:
    fmc_id: str
    interface: str
    networks: tuple[Ref, ...]
    gateway: Ref | None
    metric: int


@dataclass(frozen=True)
class BgpRecord:
    as_number: str | None
    router_id: str | None
    neighbors: tuple[dict[str, str], ...]
