"""Asset discovery: segments, user populations, domains and systems, inferred from a snapshot.

Nothing here knows a customer's names. Every verdict is the sum of independent pieces of
evidence the FMC configuration already holds, cross-checked against each other:

* **Topology** — every FTD interface with an address is a segment the FTD is the gateway of;
  every static / dynamic route is a segment behind that interface's next hop. The interface
  that carries the default route faces outside. A segment inherits the interface's zone.
* **Vocabulary** — generic words (``users``, ``switch``, ``voice``, ``mgmt``, ``dmz`` ...; not
  site names) in object, group, zone, interface and dynamic-object names.
* **Behaviour** — how rules use an address: a source towards many destinations is a client, a
  destination of specific services is a server; SIP / SCCP / RTP ports mean voice, SNMP /
  NETCONF / telnet towards it mean a network device; a source matched together with security
  group tags is managed by ISE (SD-Access).
* **Consensus** — a group or a dynamic object whose classified members mostly share one role
  lends that role to its other members (so a dynamic object that tracks the network devices is
  recognised by what it contains, whatever it is called); a segment whose addresses are mostly
  servers is a data-centre segment.
* **Domains** — learnt, not listed: short codes that qualify the names of user / voice objects
  of *several* populations (every population exists in every domain) consistently, at the start
  or the end of the name, or a realm prefix of a user condition (``DOMAIN\\user``). The
  operator's own domains are always known, deleted suggestions never come back, and a segment
  the operator assigned to a domain decides the domain of everything inside it.

Systems: servers are grouped by the smallest network group that holds mostly servers, then by
the leading distinctive token of their names (``PAY-DB01`` and ``PAY-APP02`` -> ``PAY``). The
component role comes from its name or from the services rules open to it.

The result is a set of *suggestions*. :mod:`app.api.assets` stores them unconfirmed; only what
an operator accepts feeds the analysis.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.bootstrap import TIER_TOKENS
from app.analysis.expand import Resolver
from app.models.assets import AssetDomain
from app.models.assets import Segment as SegmentRow
from app.models.inventory import Cluster, FwObject, GroupMember, Interface, Route, Rule, RuleRef

# ------------------------------------------------------------------ vocabulary

# Segment roles (the operator's list). Users and voice come in two populations: managed by ISE
# / DNA Center (SD-Access) or not (legacy).
ROLES = (
    "dc_servers",
    "sda_users",
    "legacy_users",
    "vc_sda",
    "vc_legacy",
    "network_devices",
    "management",
    "dmz",
    "outside",
    "unknown",
)


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Generic words only: a site's own names are learnt, never listed.
_WORDS: dict[str, frozenset[str]] = {
    "users": _words(
        "user users usr usrs client clients wks workstation workstations pc pcs desktop"
        " desktops paw laptop laptops endpoint endpoints vdi staff employee employees wifi wlan"
        " wireless byod guest guests"
    ),
    "voice": _words("voice voip vc phone phones ipphone ipphones ipt telephony tel uc video sip"),
    "network_devices": _words(
        "switch switches sw sws router routers rtr rtrs netdev netdevs wlc wlcs ap aps nexus"
        " catalyst"
    ),
    "management": _words(
        "mgmt mgt management oob ilo idrac ipmi bmc cimc console consoles jump bastion"
    ),
    "servers": _words(
        "srv srvs server servers svr svrs farm datacenter datacentre dc vm vms esx esxi db dbs"
        " sql app apps web"
    ),
    "dmz": _words("dmz perimeter extranet"),
    "outside": _words("outside internet inet wan isp external untrust untrusted transit"),
}
_POPULATION: dict[str, frozenset[str]] = {
    "sda": _words("sda fabric sdaccess"),
    "legacy": _words("legacy lgcy classic nonsda"),
}
# Structural tokens that say nothing about the role or the owner.
_NOISE = _words(
    "grp group groups g net nets network networks obj object objects h host hosts n r rng range"
    " ranges subnet subnets sn all list ip ips addr address addresses v4 ipv4 v6 ipv6 seg segment"
    " segments vlan vl zone z in out to from the and of dyn dynamic any new old copy tmp temp prod"
    " dev test qa stg staging lab prd pre"
)
_COMPONENT: tuple[tuple[str, frozenset[str]], ...] = (
    ("DB", _words("db dbs sql mssql ora oracle mysql pg postgres postgresql mongo redis")),
    ("Web", _words("web www iis nginx apache fe front frontend portal")),
    ("App", _words("app apps as be backend api svc service")),
    ("LB", _words("lb f5 adc vip")),
    ("File", _words("fs file files nas smb nfs")),
)
_DB_PORTS = frozenset({1433, 1521, 3306, 5432, 27017, 6379, 50000})
_WEB_PORTS = frozenset({80, 443, 8080, 8443})
_VOICE_PORTS = frozenset({5060, 5061, 2000, 1720})
_RTP = (16384, 32767)
_NETDEV_PORTS = frozenset({161, 23, 830})

_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")

# Evidence weights.
W_OWN_NAME = 3.0
W_GROUP_NAME = 1.5
W_DYNAMIC_NAME = 2.0
W_CONSENSUS = 2.0
W_TOPOLOGY = 2.0
W_BEHAVIOUR = 1.0
THRESHOLD = 2.0  # a role needs at least this much evidence
MAX_GROUP_LEAVES = 2000  # bigger groups are "everything" groups: their names prove nothing
SYSTEM_GROUP_MAX = 64  # a group this size or smaller can be one system
MIN_PREFIX = 8


def tokens(name: str) -> list[str]:
    """Lower-case word tokens of a name: split on punctuation, case changes and digits."""
    out: list[str] = []
    for part in _SPLIT.split(name):
        out.extend(p.lower() for p in _CAMEL.split(part) if p)
    return out


def word_roles(words: Iterable[str]) -> set[str]:
    found = set(words)
    return {role for role, vocabulary in _WORDS.items() if found & vocabulary}


def population(words: Iterable[str]) -> str | None:
    found = set(words)
    for pop, vocabulary in _POPULATION.items():
        if found & vocabulary:
            return pop
    if {"non", "sda"} <= found:
        return "legacy"
    return None


def _qualifiers(words: Iterable[str]) -> list[str]:
    """Tokens left once vocabulary, population words, noise and numbers are removed."""
    vocabulary = set().union(*_WORDS.values(), *_POPULATION.values(), _NOISE)
    return [w for w in words if w not in vocabulary and not w.isdigit() and len(w) >= 2]


def _edge_codes(name: str) -> set[str]:
    """Qualifiers at the start or the end of a name (where a domain code sits)."""
    kept = [w for w in tokens(name) if not w.isdigit()]
    if not kept:
        return set()
    return set(_qualifiers([kept[0], kept[-1]]))


def tier_of(names: Iterable[str]) -> str | None:
    words = {w.upper() for n in names for w in tokens(n)}
    for tier, keywords in TIER_TOKENS:
        if words & keywords:
            return tier
    return None


# ------------------------------------------------------------------ facts


@dataclass
class Unit:
    """An address block defined by one or more objects (a host, a network or a range)."""

    network: str
    names: set[str] = field(default_factory=set)  # objects that define it
    groups: set[str] = field(default_factory=set)  # group ids that contain it (any depth)
    dynamics: set[str] = field(default_factory=set)  # dynamic object ids that map it
    as_src: int = 0
    as_dst: int = 0
    dst_ports: Counter[int] = field(default_factory=Counter)
    netdev_hits: int = 0
    voice_hits: int = 0
    sgt_hits: int = 0
    # Results.
    scores: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    evidence: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    pop_votes: dict[str, float] = field(default_factory=lambda: defaultdict(float))

    @property
    def is_host(self) -> bool:
        return self.network.endswith("/32") or self.network.endswith("/128")

    def add(self, role: str, weight: float, why: str) -> None:
        self.scores[role] += weight
        if len(self.evidence[role]) < 6 and why not in self.evidence[role]:
            self.evidence[role].append(why)

    def role(self) -> tuple[str | None, float]:
        if not self.scores:
            return None, 0.0
        role, top = max(self.scores.items(), key=lambda kv: (kv[1], kv[0]))
        if top < THRESHOLD:
            return None, 0.0
        total = sum(self.scores.values())
        return role, top / total if total else 0.0


@dataclass
class Segment:
    network: str
    role: str = "unknown"
    domain: str | None = None
    cluster: str = ""
    interface: str = ""
    zone: str = ""
    gateway: bool = False  # the FTD is this segment's gateway (connected interface)
    in_dc: bool = False
    confidence: float = 0.0
    evidence: list[dict[str, str]] = field(default_factory=list)
    name: str = ""
    hints: set[str] = field(default_factory=set)  # roles its zone / interface names suggest
    tier_hint: str | None = None

    def why(self, source: str, detail: str) -> None:
        if len(self.evidence) < 12:
            self.evidence.append({"source": source, "detail": detail[:200]})


@dataclass
class Facts:
    units: dict[str, Unit]
    groups: dict[str, tuple[str, set[str]]]  # group id -> (name, leaf networks)
    dynamics: dict[str, tuple[str, set[str]]]  # dynamic id -> (name, mapped networks)
    interfaces: list[dict[str, Any]]  # cluster, interface, ifname, zone, network, gateway ip
    routes: list[dict[str, Any]]  # cluster, ifname, network, gateway
    realms: Counter[str]  # DOMAIN prefixes of user conditions
    sgt_names: list[str]
    live_groups: set[str] = field(default_factory=set)  # used by a rule, directly or nested
    # The operator's decisions, which outrank every inference:
    known_domains: set[str] = field(default_factory=set)  # confirmed / added (lower case)
    rejected_domains: set[str] = field(default_factory=set)  # deleted suggestions (lower case)
    domain_ranges: list[tuple[str, str]] = field(default_factory=list)  # (network, DOMAIN)


def _canonical(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    try:
        if "-" in text:
            start, _, end = text.partition("-")
            a, b = ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
            return f"{a}-{b}"
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if net.version == 4 and net.prefixlen < MIN_PREFIX:
        return None
    return str(net)


def _ports(value: str | None) -> list[int]:
    """``TCP/443`` -> [443]; ranges give their ends (and RTP is recognised by the caller)."""
    if not value or "/" not in value:
        return []
    _, _, spec = value.partition("/")
    out: list[int] = []
    for part in spec.split("-"):
        if part.strip().isdigit():
            out.append(int(part))
    return out


def load_facts(session: Session, snapshot_id: int) -> Facts:
    objects = session.execute(
        select(FwObject.fmc_id, FwObject.kind, FwObject.name, FwObject.value, FwObject.attrs).where(
            FwObject.snapshot_id == snapshot_id, FwObject.stub.is_(False)
        )
    ).all()
    resolver = Resolver.load(session, snapshot_id)
    units: dict[str, Unit] = {}
    by_object: dict[str, set[str]] = defaultdict(set)  # object id -> networks
    names: dict[str, str] = {}
    zones: dict[str, str] = {}
    groups: dict[str, tuple[str, set[str]]] = {}
    dynamics: dict[str, tuple[str, set[str]]] = {}
    sgt_names: list[str] = []

    def unit(network: str) -> Unit:
        if network not in units:
            units[network] = Unit(network)
        return units[network]

    for fid, kind, name, value, attrs in objects:
        names[fid] = name
        if kind in ("host", "network", "range"):
            network = _canonical(value)
            if network is not None:
                unit(network).names.add(name)
                by_object[fid].add(network)
        elif kind == "zone":
            zones[fid] = name
        elif kind == "sgt":
            sgt_names.append(name)
        elif kind == "dynamic":
            mapped = {n for n in (_canonical(m) for m in (attrs or {}).get("mappings") or []) if n}
            dynamics[fid] = (name, mapped)
            for network in mapped:
                unit(network).dynamics.add(fid)
            by_object[fid] |= mapped
    for fid, kind, name, _value, _attrs in objects:
        if kind != "network_group":
            continue
        leaves = {n for n in (_canonical(a) for a in resolver.leaves(fid).addresses) if n}
        groups[fid] = (name, leaves)
        by_object[fid] |= leaves
        if len(leaves) <= MAX_GROUP_LEAVES:
            for network in leaves:
                unit(network).groups.add(fid)

    # Behaviour: how enabled permitting access rules use each address.
    refs: dict[int, dict[str, list[tuple[str | None, str | None]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for rule_id, fld, oid, literal in session.execute(
        select(RuleRef.rule_id, RuleRef.field, RuleRef.object_fmc_id, RuleRef.literal)
        .join(Rule, Rule.id == RuleRef.rule_id)
        .where(
            Rule.snapshot_id == snapshot_id,
            Rule.enabled.is_(True),
            Rule.action.in_(["ALLOW", "TRUST", "FASTPATH"]),
            RuleRef.field.in_(["src_net", "dst_net", "dst_port", "src_sgt", "user"]),
        )
    ).all():
        refs[rule_id][fld].append((oid, literal))
    port_values = {fid: value for fid, kind, _n, value, _a in objects if kind == "port"}
    port_members: dict[str, list[str]] = {}
    realms: Counter[str] = Counter()

    def nets(items: list[tuple[str | None, str | None]]) -> set[str]:
        out: set[str] = set()
        for oid, literal in items:
            if oid is not None:
                out |= by_object.get(oid, set())
            elif literal:
                n = _canonical(literal)
                if n:
                    out.add(n)
        return out

    def ports(items: list[tuple[str | None, str | None]]) -> list[int]:
        out: list[int] = []
        for oid, literal in items:
            if oid is not None and oid in port_values:
                out += _ports(port_values[oid])
            elif oid is not None:
                if oid not in port_members:
                    port_members[oid] = list(resolver.leaves(oid).ports)
                for value in port_members[oid]:
                    out += _ports(value)
            elif literal:
                out += _ports(literal)
        return out

    for fields in refs.values():
        src, dst = nets(fields.get("src_net", [])), nets(fields.get("dst_net", []))
        dports = ports(fields.get("dst_port", []))
        voice = any(p in _VOICE_PORTS or _RTP[0] <= p <= _RTP[1] for p in dports)
        netdev = any(p in _NETDEV_PORTS for p in dports)
        sgt = bool(fields.get("src_sgt"))
        for oid, _literal in fields.get("user", []):
            user = names.get(oid or "", "")
            if "\\" in user:
                realms[user.split("\\", 1)[0].lower()] += 1
        wide_dst = not dst or len(dst) > 20
        for n in src:
            u = units.get(n)
            if u is None:
                continue
            u.as_src += 2 if wide_dst else 1
            u.voice_hits += voice
            u.sgt_hits += sgt
        for n in dst:
            u = units.get(n)
            if u is None:
                continue
            u.as_dst += 1
            u.voice_hits += voice
            u.netdev_hits += netdev
            u.dst_ports.update(p for p in dports if p < 49152)

    # Topology.
    cluster_names = dict(
        session.execute(
            select(Cluster.fmc_id, Cluster.name).where(Cluster.snapshot_id == snapshot_id)
        ).all()
    )
    interfaces: list[dict[str, Any]] = []
    for cid, name, ifname, zone_id, ipv4 in session.execute(
        select(
            Interface.cluster_fmc_id,
            Interface.name,
            Interface.ifname,
            Interface.zone_fmc_id,
            Interface.ipv4,
        ).where(Interface.snapshot_id == snapshot_id, Interface.ipv4.is_not(None))
    ).all():
        try:
            iface = ipaddress.ip_interface(str(ipv4))
        except ValueError:
            continue
        interfaces.append(
            {
                "cluster": cluster_names.get(cid, cid),
                "interface": name,
                "ifname": ifname or "",
                "zone": zones.get(zone_id or "", ""),
                "network": str(iface.network),
                "address": str(iface.ip),
            }
        )
    routes: list[dict[str, Any]] = []
    for cid, _kind, ifname, network, gateway in session.execute(
        select(
            Route.cluster_fmc_id, Route.kind, Route.interface, Route.network, Route.gateway
        ).where(Route.snapshot_id == snapshot_id, Route.kind.in_(["static", "dynamic"]))
    ).all():
        routes.append(
            {
                "cluster": cluster_names.get(cid, cid),
                "ifname": ifname or "",
                "network": network or "",
                "gateway": gateway or "",
            }
        )
    # Groups a rule uses, directly or through a parent group: only those can define a system.
    children: dict[str, list[str]] = defaultdict(list)
    for parent, child in session.execute(
        select(GroupMember.group_fmc_id, GroupMember.member_fmc_id).where(
            GroupMember.snapshot_id == snapshot_id, GroupMember.member_fmc_id.is_not(None)
        )
    ).all():
        children[parent].append(str(child))
    used = set(
        session.scalars(
            select(RuleRef.object_fmc_id)
            .join(Rule, Rule.id == RuleRef.rule_id)
            .where(Rule.snapshot_id == snapshot_id, RuleRef.object_fmc_id.is_not(None))
            .distinct()
        )
    )
    live: set[str] = set()
    stack = [g for g in used if g in groups]
    while stack:
        g = stack.pop()
        if g in live:
            continue
        live.add(g)
        stack.extend(c for c in children.get(g, []) if c in groups)
    return Facts(units, groups, dynamics, interfaces, routes, realms, sgt_names, live)


# ------------------------------------------------------------------ inference


@dataclass
class SystemSuggestion:
    name: str
    kind: str  # system | server
    tier: str
    domain: str | None
    components: list[tuple[str, str, str]]  # (network, component name, role)
    evidence: list[dict[str, str]]
    confidence: float


@dataclass
class Discovery:
    segments: list[Segment]
    systems: list[SystemSuggestion]  # servers, network devices, management, user populations
    domains: dict[str, list[dict[str, str]]]  # domain -> evidence
    unit_roles: dict[str, str]


def _segment_role(unit_role: str, pop: str | None) -> str:
    if unit_role == "users":
        return "sda_users" if pop == "sda" else "legacy_users"
    if unit_role == "voice":
        return "vc_sda" if pop == "sda" else "vc_legacy"
    if unit_role == "servers":
        return "dc_servers"
    return unit_role


def _net(network: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "-" in network:
        return None
    try:
        return ipaddress.ip_network(network, strict=False)
    except ValueError:
        return None


class _SegmentIndex:
    """Longest-prefix lookup of the topology segments."""

    def __init__(self, segments: Iterable[Segment]) -> None:
        self.items = sorted(
            ((n, s) for s in segments if (n := _net(s.network)) is not None),
            key=lambda x: -x[0].prefixlen,
        )

    def find(self, network: str) -> Segment | None:
        target = _net(network)
        if target is None:
            start = network.split("-", 1)[0]
            try:
                target = ipaddress.ip_network(start)
            except ValueError:
                return None
        for net, seg in self.items:
            if net.version == target.version and target.subnet_of(net):  # type: ignore[arg-type]
                return seg
        return None


def _behaviour(u: Unit) -> None:
    if u.voice_hits >= 2:
        u.add("voice", W_BEHAVIOUR * 1.5, f"rules open voice ports for it ({u.voice_hits})")
    if u.netdev_hits >= 1 and u.is_host:
        u.add("network_devices", W_BEHAVIOUR * 1.5, "rules open SNMP / NETCONF / telnet to it")
    if u.as_src >= 3 and u.as_src > 3 * u.as_dst and not u.is_host:
        u.add("users", W_BEHAVIOUR, f"a source towards many destinations ({u.as_src} rules)")
    if u.as_dst >= 1 and u.as_dst >= u.as_src and u.dst_ports:
        top = ", ".join(str(p) for p, _ in u.dst_ports.most_common(3))
        u.add("servers", W_BEHAVIOUR, f"a destination of services {top}")
    if u.sgt_hits:
        u.pop_votes["sda"] += 1.5
        u.evidence["population"].append(f"matched with security group tags in {u.sgt_hits} rules")


def _names(u: Unit, facts: Facts) -> None:
    for name in sorted(u.names):
        words = tokens(name)
        for role in word_roles(words):
            u.add(role, W_OWN_NAME, f"object {name}")
        pop = population(words)
        if pop:
            u.pop_votes[pop] += W_OWN_NAME
    for gid in sorted(u.groups):
        gname, _ = facts.groups[gid]
        words = tokens(gname)
        for role in word_roles(words):
            u.add(role, W_GROUP_NAME, f"inside group {gname}")
        pop = population(words)
        if pop:
            u.pop_votes[pop] += W_GROUP_NAME
    for did in sorted(u.dynamics):
        dname, _ = facts.dynamics[did]
        for role in word_roles(tokens(dname)):
            u.add(role, W_DYNAMIC_NAME, f"mapped by dynamic object {dname}")


def _consensus(facts: Facts, roles: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Groups and dynamic objects whose classified members mostly share one role."""
    out: dict[str, tuple[str, str]] = {}
    for oid, (name, members) in [*facts.dynamics.items(), *facts.groups.items()]:
        if len(members) < 3 or len(members) > MAX_GROUP_LEAVES:
            continue
        votes = Counter(roles[m] for m in members if m in roles)
        if not votes:
            continue
        role, count = votes.most_common(1)[0]
        classified = sum(votes.values())
        if count >= 3 and count / classified >= 0.7 and classified / len(members) >= 0.3:
            out[oid] = (role, f"{name}: {count} of its {len(members)} addresses are {role}")
    return out


def discover(facts: Facts) -> Discovery:
    # 1. Topology segments.
    segments: dict[str, Segment] = {}
    default_ifaces = {
        (r["cluster"], r["ifname"]) for r in facts.routes if r["network"] in ("0.0.0.0/0", "::/0")
    }
    iface_by_name = {(i["cluster"], i["ifname"]): i for i in facts.interfaces}
    for i in facts.interfaces:
        seg = segments.setdefault(i["network"], Segment(i["network"]))
        seg.cluster, seg.interface, seg.zone, seg.gateway = (
            i["cluster"],
            f"{i['interface']} ({i['ifname']})" if i["ifname"] else i["interface"],
            i["zone"],
            True,
        )
        seg.name = i["ifname"] or i["zone"] or i["interface"]
        seg.why(
            "interface",
            f"{i['cluster']} {i['interface']} {i['ifname']} {i['address']}"
            f" — the FTD is the gateway",
        )
    for r in facts.routes:
        network = _canonical(r["network"])
        if network is None or network in ("0.0.0.0/0", "::/0"):
            continue
        seg = segments.setdefault(network, Segment(network))
        iface = iface_by_name.get((r["cluster"], r["ifname"]))
        if not seg.gateway:
            seg.cluster, seg.interface = r["cluster"], r["ifname"]
            seg.zone = iface["zone"] if iface else ""
            seg.name = seg.name or r["ifname"]
        seg.why("route", f"{r['cluster']}: via {r['ifname']} next hop {r['gateway']}")
    for seg in segments.values():
        words = tokens(seg.zone) + tokens(seg.interface) + tokens(seg.name)
        seg_roles = word_roles(words)
        seg.hints = seg_roles
        if (seg.cluster, seg.interface.split(" (")[0]) in default_ifaces or (
            seg.cluster,
            seg.name,
        ) in default_ifaces:
            seg.hints = {"outside"}
            seg.why("route", "the interface carries the default route")
        seg.tier_hint = tier_of([seg.zone, seg.name])
    index = _SegmentIndex(segments.values())

    # 2. Units: names, behaviour, topology.
    for u in facts.units.values():
        _names(u, facts)
        _behaviour(u)
        home = index.find(u.network)
        if home is not None:
            for role in home.hints:
                u.add(role, W_TOPOLOGY, f"in segment {home.network} ({home.name or home.zone})")
            if home.tier_hint is not None and not home.hints:
                # A tier-named zone (GOLD, SILVER ...) holds servers.
                u.add("servers", W_TOPOLOGY, f"in tier segment {home.network} ({home.name})")

    # 3. Consensus of groups / dynamic objects, twice (a propagation may unlock another).
    for _round in range(2):
        current = {n: got for n, x in facts.units.items() if (got := x.role()[0]) is not None}
        for oid, (role, why) in _consensus(facts, current).items():
            members = facts.dynamics.get(oid, facts.groups.get(oid, ("", set())))[1]
            for m in members:
                member = facts.units.get(m)
                if member is not None and why not in member.evidence[role]:
                    member.add(role, W_CONSENSUS, why)

    roles: dict[str, str] = {}
    for n, x in facts.units.items():
        verdict = x.role()[0]
        if verdict is not None:
            roles[n] = verdict

    # 4. Domains: qualifiers of user / voice names that recur across populations (or realms).
    domains = _domains(facts, roles)
    ranges = _DomainRanges(facts.domain_ranges)

    def domain_of(u: Unit) -> str | None:
        fixed = ranges.find(u.network)  # an operator's segment -> domain decision wins
        if fixed is not None:
            return fixed
        names = list(u.names) + [
            facts.groups[g][0] for g in u.groups if len(facts.groups[g][1]) <= 256
        ]
        hits = Counter(q for name in names for q in _edge_codes(name) if q in domains)
        return hits.most_common(1)[0][0].upper() if hits else None

    # 5. Segments: topology segments get the role of what they hold; network units join.
    held: dict[str, Counter[str]] = defaultdict(Counter)
    for n, role in roles.items():
        container = index.find(n)
        if container is not None and container.network != n:
            held[container.network][role] += 1
    for seg in segments.values():
        own = seg.hints
        votes = held.get(seg.network, Counter())
        if "outside" in own:
            seg.role, seg.confidence = "outside", 0.9
        elif own:
            role = sorted(own)[0]
            seg.role = _segment_role(role, None)
            seg.confidence = 0.6
            seg.why("names", f"zone / interface named {seg.zone or seg.name}")
        if votes:
            role, c = votes.most_common(1)[0]
            share = c / sum(votes.values())
            if share >= 0.6 and (not own or seg.role == "unknown"):
                seg.role = _segment_role(role, None)
                seg.confidence = round(min(0.9, share), 2)
                seg.why(
                    "composition", f"{c} of {sum(votes.values())} classified addresses are {role}"
                )
        elif seg.tier_hint is not None and seg.role == "unknown":
            seg.role, seg.confidence = "dc_servers", 0.5
            seg.why("names", f"tier zone {seg.zone or seg.name}")
    for n, role in roles.items():
        u = facts.units[n]
        if u.is_host or role in ("outside",):
            continue
        pvotes = u.pop_votes
        upop = max(pvotes, key=lambda k: pvotes[k]) if pvotes else None
        seg = segments.get(n) or Segment(n, name=sorted(u.names)[0] if u.names else n)
        segments[n] = seg
        _, conf = u.role()
        if seg.role == "unknown" or not seg.gateway:
            seg.role = _segment_role(role, upop)
            seg.confidence = round(conf, 2)
        for why in u.evidence[role][:4]:
            seg.why("names" if why.startswith(("object", "inside", "mapped")) else "behaviour", why)
        for why in u.evidence.get("population", [])[:1]:
            seg.why("identity", why)
        seg.domain = seg.domain or domain_of(u)
        parent = index.find(n)
        if parent is not None and parent.network != n:
            seg.cluster = seg.cluster or parent.cluster
            seg.interface = seg.interface or parent.interface
            seg.zone = seg.zone or parent.zone
    for seg in segments.values():
        if (
            seg.role in ("sda_users", "legacy_users", "vc_sda", "vc_legacy")
            and not any(e["source"] == "identity" for e in seg.evidence)
            and seg.role in ("legacy_users", "vc_legacy")
        ):
            seg.why("identity", "no ISE / security group tag evidence")
        seg.in_dc = seg.role == "dc_servers"
        seg.domain = ranges.find(seg.network) or seg.domain

    # 6. Systems and population assets.
    systems = _systems(facts, roles, index, domain_of)
    return Discovery(
        sorted(segments.values(), key=lambda s: _sort_key(s.network)), systems, domains, roles
    )


MAX_DOMAIN_LEN = 6  # a domain is a short code (AH, LOTR ...), not a descriptive word
MIN_DOMAIN_OBJECTS = 3
DOMAIN_EDGE_SHARE = 0.75  # how often the qualifier sits at the start or the end of the name
DOMAIN_MIN_SHARE = 0.05  # of the most used domain's objects


def _domains(facts: Facts, roles: dict[str, str]) -> dict[str, list[dict[str, str]]]:
    """Domains: realm prefixes of user conditions, the operator's own domains, and short codes
    that qualify user / voice objects of several populations consistently (same edge of the
    name, several objects and networks). Rejected suggestions never come back."""
    pops: dict[str, set[str]] = defaultdict(set)  # qualifier -> populations
    objects: dict[str, set[str]] = defaultdict(set)  # qualifier -> object / group names
    units: dict[str, set[str]] = defaultdict(set)  # qualifier -> networks
    edge: Counter[str] = Counter()  # qualifier -> names where it is the first / last token
    for n, role in roles.items():
        if role not in ("users", "voice"):
            continue
        u = facts.units[n]
        for name in u.names | {
            facts.groups[g][0] for g in u.groups if len(facts.groups[g][1]) <= 256
        }:
            words = tokens(name)
            pop = (population(words) or "plain") + (
                "-voice" if "voice" in word_roles(words) else ""
            )
            kept = [w for w in words if not w.isdigit()]
            for q in set(_qualifiers(words)):
                if any(c.isdigit() for c in q) or len(q) > MAX_DOMAIN_LEN:
                    continue
                pops[q].add(pop)
                units[q].add(n)
                if name not in objects[q]:
                    objects[q].add(name)
                    edge[q] += bool(kept) and q in (kept[0], kept[-1])
    found: dict[str, list[dict[str, str]]] = {}
    for q in sorted(facts.known_domains):
        found[q] = [{"source": "operator", "detail": "a domain the operator confirmed or added"}]
    for realm, hits in facts.realms.items():
        found.setdefault(
            realm, [{"source": "identity", "detail": f"realm prefix in {hits} user conditions"}]
        )
    candidates = {
        q
        for q, p in pops.items()
        if len(p) >= 2
        and len(objects[q]) >= MIN_DOMAIN_OBJECTS
        and len(units[q]) >= 2
        and edge[q] >= DOMAIN_EDGE_SHARE * len(objects[q])
    }
    if candidates:
        floor = DOMAIN_MIN_SHARE * max(len(objects[q]) for q in candidates)
        for q in sorted(candidates):
            if len(objects[q]) < floor:
                continue
            found.setdefault(
                q,
                [
                    {
                        "source": "names",
                        "detail": (
                            f"qualifies {len(objects[q])} user / voice objects of"
                            f" {len(pops[q])} populations ({', '.join(sorted(pops[q]))})"
                        ),
                    }
                ],
            )
    return {q: e for q, e in found.items() if q not in facts.rejected_domains}


class _DomainRanges:
    """Longest-prefix lookup of the operator's segment -> domain decisions."""

    def __init__(self, ranges: Iterable[tuple[str, str]]) -> None:
        self.items = sorted(
            ((n, d) for network, d in ranges if (n := _net(network)) is not None),
            key=lambda x: -x[0].prefixlen,
        )

    def find(self, network: str) -> str | None:
        if not self.items:
            return None
        targets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        single = _net(network)
        if single is not None:
            targets.append(single)
        else:  # a range: both ends must be inside
            try:
                targets += [ipaddress.ip_network(x.strip()) for x in network.split("-", 1)]
            except ValueError:
                return None
        for net, domain in self.items:
            if all(
                t.version == net.version and t.subnet_of(net)  # type: ignore[arg-type]
                for t in targets
            ):
                return domain
        return None


def _sort_key(network: str) -> tuple[int, int, int]:
    n = _net(network)
    if n is None:
        start = network.split("-", 1)[0]
        try:
            a = ipaddress.ip_address(start)
        except ValueError:
            return (9, 0, 0)
        return (a.version, int(a), 0)
    return (n.version, int(n.network_address), n.prefixlen)


_TIER_NAMES = frozenset({"gold", "silver", "bronze", "core"})
_GENERIC = _words("sys system systems svc service services srv srvs server servers")


def _system_key(name: str) -> str | None:
    """The leading distinctive token of a name (``H_PAY-DB_19`` -> ``PAY``); failing that, the
    first meaningful word even if generic (``H_DC_01`` -> ``DC``)."""
    component_words = set().union(*(w for _, w in _COMPONENT))
    vocabulary = set().union(*_WORDS.values(), *_POPULATION.values())
    words = [w for w in tokens(name) if w not in _NOISE and not w.isdigit() and len(w) >= 2]
    for w in words:
        if w in component_words or w in vocabulary or w in _TIER_NAMES or w in _GENERIC:
            continue
        return w.upper()
    for w in words:
        if w not in _TIER_NAMES and w not in _GENERIC:
            return w.upper()
    return None


def _group_system_name(name: str) -> str:
    """A group's name without its leading structural words (``GRP_SYS_PAY-DB`` -> ``PAY-DB``)."""
    parts = [p for p in re.split(r"[_\s.]+", name) if p]
    while len(parts) > 1 and parts[0].lower() in _NOISE | _GENERIC:
        parts.pop(0)
    return "_".join(parts)[:128] or name[:128]


def _second_key(name: str, first: str) -> str | None:
    """The meaningful token after ``first`` in a name (``H_DMZ_WEB01_01``, DMZ -> ``WEB01``)."""
    parts = [p for p in re.split(r"[_\s.-]+", name) if p]
    upper = [p.upper() for p in parts]
    if first not in upper:
        return None
    for p in upper[upper.index(first) + 1 :]:
        if not p.isdigit() and p.lower() not in _NOISE and len(p) >= 2:
            return p
    return None


def _component_role(names: Iterable[str], u: Unit) -> str:
    words = {w for n in names for w in tokens(n)}
    for role, vocabulary in _COMPONENT:
        if words & vocabulary:
            return role
    ports = set(u.dst_ports)
    if ports & _DB_PORTS:
        return "DB"
    if ports & _WEB_PORTS:
        return "Web"
    return ""


def _systems(
    facts: Facts, roles: dict[str, str], index: _SegmentIndex, domain_of: Any
) -> list[SystemSuggestion]:
    out: list[SystemSuggestion] = []
    servers = [n for n, r in roles.items() if r in ("servers", "dmz") and facts.units[n].is_host]

    def tier(names: list[str], members: list[str]) -> tuple[str, dict[str, str]]:
        """The tier zone most members sit behind (the FTD's own segmentation); else a tier
        word in the names; else SILVER."""
        zones = Counter(seg.tier_hint for n in members if (seg := index.find(n)) and seg.tier_hint)
        if zones:
            t, c = zones.most_common(1)[0]
            return t, {"source": "topology", "detail": f"{c} of {len(members)} behind a {t} zone"}
        named = tier_of(names)
        if named is not None:
            return named, {"source": "names", "detail": f"tier {named} in the names"}
        return "SILVER", {"source": "default", "detail": "no tier evidence: SILVER until reviewed"}

    assigned: dict[str, str] = {}
    # a. The smallest group holding mostly servers is the system.
    candidates = []
    for gid, (gname, leaves) in facts.groups.items():
        if gid not in facts.live_groups or not 2 <= len(leaves) <= SYSTEM_GROUP_MAX:
            continue
        server_leaves = [n for n in leaves if roles.get(n) in ("servers", "dmz")]
        if len(server_leaves) / len(leaves) >= 0.8 and _system_key(gname):
            candidates.append((len(leaves), gname, gid, server_leaves))
    names_of: dict[str, tuple[str, list[str], str]] = {}
    for _size, gname, _gid, server_leaves in sorted(candidates):
        key = _group_system_name(gname)
        for n in server_leaves:
            if n not in assigned:
                assigned[n] = key
                names_of.setdefault(key, (gname, [], "group"))[1].append(n)
    # b. The leading token of the server's own names; a family too large to be one system
    # (a naming scheme, not a system) is split by its next token.
    families: dict[str, list[str]] = defaultdict(list)
    for n in servers:
        if n in assigned:
            continue
        keys = Counter(k for name in facts.units[n].names if (k := _system_key(name)))
        if keys:
            families[keys.most_common(1)[0][0]].append(n)
    for key, members in families.items():
        for n in members:
            sub = key
            if len(members) > SYSTEM_GROUP_MAX:
                nexts = Counter(k for name in facts.units[n].names if (k := _second_key(name, key)))
                if nexts:
                    sub = f"{key}-{nexts.most_common(1)[0][0]}"
            assigned[n] = sub
            names_of.setdefault(sub, (sub, [], "names"))[1].append(n)
    singles: list[str] = [n for n in servers if n not in assigned]
    for key, (label, members, how) in sorted(names_of.items()):
        if len(members) < 2:
            singles.extend(members)
            continue
        comps = []
        all_names: list[str] = [label]
        for n in sorted(members, key=_sort_key):
            u = facts.units[n]
            cname = sorted(u.names)[0] if u.names else n
            all_names += list(u.names)
            comps.append((n, cname[:128], _component_role(u.names, u)))
        sys_tier, tier_why = tier(all_names, members)
        domains = Counter(d for n in members if (d := domain_of(facts.units[n])))
        out.append(
            SystemSuggestion(
                name=key,
                kind="system",
                tier=sys_tier,
                domain=domains.most_common(1)[0][0] if domains else None,
                components=comps,
                evidence=[
                    {
                        "source": "names" if how == "names" else "group",
                        "detail": f"{len(members)} servers share "
                        + ("the name " if how == "names" else "group ")
                        + label,
                    },
                    tier_why,
                ],
                confidence=0.7 if how == "group" else 0.6,
            )
        )
    for n in sorted(singles, key=_sort_key):
        u = facts.units[n]
        name = sorted(u.names)[0] if u.names else n
        out.append(
            SystemSuggestion(
                name=name[:128],
                kind="server",
                tier=tier(sorted(u.names), [n])[0],
                domain=domain_of(u),
                components=[(n, name[:128], _component_role(u.names, u))],
                evidence=[
                    {
                        "source": "behaviour" if not u.names else "names",
                        "detail": "; ".join(u.evidence[roles[n]][:2]),
                    }
                ],
                confidence=round(u.role()[1], 2),
            )
        )
    # c. Network devices and management: one asset per domain.
    for role, label in (("network_devices", "Network devices"), ("management", "Management")):
        buckets: dict[str | None, list[str]] = defaultdict(list)
        for n, r in roles.items():
            if r == role:
                buckets[domain_of(facts.units[n])].append(n)
        for domain, members in sorted(buckets.items(), key=lambda kv: kv[0] or ""):
            whys = Counter(w for n in members for w in facts.units[n].evidence[role][:2])
            out.append(
                SystemSuggestion(
                    name=f"{label} {domain}" if domain else label,
                    kind="system",
                    tier="CORE",
                    domain=domain,
                    components=[
                        (n, (sorted(facts.units[n].names) or [n])[0][:128], label)
                        for n in sorted(members, key=_sort_key)
                    ],
                    evidence=[
                        {"source": "consensus" if ":" in w else "names", "detail": w}
                        for w, _ in whys.most_common(4)
                    ],
                    confidence=0.7,
                )
            )
    # d. User populations: one asset per population and domain (networks, not single hosts).
    pops: dict[tuple[str, str | None], list[str]] = defaultdict(list)
    for n, r in roles.items():
        u = facts.units[n]
        if r not in ("users", "voice") or u.is_host:
            continue
        pop = max(u.pop_votes, key=lambda k: u.pop_votes[k]) if u.pop_votes else None
        pops[(_segment_role(r, pop), domain_of(u))].append(n)
    for (role, domain), members in sorted(pops.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        label = USER_TYPE[role]
        out.append(
            SystemSuggestion(
                name=f"{label} {domain}" if domain else label,
                kind="user_segment",
                tier="USERS",
                domain=domain,
                components=[
                    (n, (sorted(facts.units[n].names) or [n])[0][:128], "")
                    for n in sorted(members, key=_sort_key)
                ],
                evidence=[{"source": "names", "detail": f"{len(members)} user networks"}],
                confidence=0.6,
            )
        )
    return out


# Segment role -> the user_type a user population asset carries.
USER_TYPE = {
    "sda_users": "SDA-USERS",
    "legacy_users": "LEGACY-USERS",
    "vc_sda": "VC-SDA",
    "vc_legacy": "VC-LEGACY",
}


def run(session: Session, snapshot_id: int) -> Discovery:
    facts = load_facts(session, snapshot_id)
    for name, source, confirmed, rejected in session.execute(
        select(AssetDomain.name, AssetDomain.source, AssetDomain.confirmed, AssetDomain.rejected)
    ).all():
        if rejected:
            facts.rejected_domains.add(name.lower())
        elif confirmed or source == "manual":
            facts.known_domains.add(name.lower())
    facts.domain_ranges = [
        (network, domain)
        for network, domain in session.execute(
            select(SegmentRow.network, SegmentRow.domain).where(
                SegmentRow.domain.is_not(None),
                (SegmentRow.source == "manual") | SegmentRow.confirmed.is_(True),
            )
        ).all()
        if domain
    ]
    return discover(facts)
