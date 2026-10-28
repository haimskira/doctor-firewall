"""A large, messy but doctrine-shaped rulebase for a LAB FMC (pure data, no I/O).

An enterprise address plan (CORE / GOLD / SILVER / BRONZE servers, user segments, DMZ, partners)
and a rulebase grown the way real ones grow: sound rules first, then years of exceptions —
duplicate objects under address-style names, groups nested eight deep, groups mixing tiers,
duplicate and shadowed rules, rules that only differ by source, rules spanning several tiers,
wide ports, inline values, tier skips, Trust to GOLD, GOLD without IPS, disabled leftovers and a
few "temporary" any rules. ``build(seed, objects, rules)`` is deterministic.

``build_policies(seed, names, objects, rules)`` is the pre-production dry run: one object pool and
one rulebase per access policy, with what the later phases look at too — services declared in the
asset table (port tightening), dynamic objects with mappings, and "allow" rules from bogon sources
that a prefilter BLOCK rule drops first (attack surface).
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from typing import Any

TIERS = ("CORE", "GOLD", "SILVER", "BRONZE")
CATEGORIES = (
    "Infra-Core",
    "Users-to-Apps",
    "Apps-to-DB",
    "Admin-Access",
    "DMZ-Inbound",
    "Partners",
    "Projects-2019",
    "Projects-2021",
    "Projects-2023",
    "Migration",
    "Temp-Exceptions",
    "Vendors",
    "Monitoring",
    "Backup",
    "Legacy",
)
DEPARTMENTS = (
    "FIN",
    "HR",
    "IT",
    "SALES",
    "ENG",
    "OPS",
    "LEGAL",
    "MKT",
    "SUPPORT",
    "RND",
    "PROC",
    "SEC",
    "BI",
    "CALL",
    "EXEC",
)
GOLD_SYSTEMS = (
    "FIN-DB",
    "PAY-DB",
    "HR-DB",
    "CRM-DB",
    "ERP-DB",
    "BILL-DB",
    "CARD-DB",
    "TAX-DB",
    "AUDIT-DB",
    "CORE-BANK",
    "TREASURY",
    "LEDGER",
    "RISK-DB",
    "KYC-DB",
    "VAULT",
    "HSM",
    "SAP-PRD",
    "DWH-PRD",
    "MDM-PRD",
    "IAM-DB",
)
SERVICES = {
    "HTTPS": ("TCP", "443"),
    "HTTP": ("TCP", "80"),
    "ALT-HTTPS": ("TCP", "8443"),
    "MSSQL": ("TCP", "1433"),
    "ORACLE": ("TCP", "1521"),
    "POSTGRES": ("TCP", "5432"),
    "MYSQL": ("TCP", "3306"),
    "SSH": ("TCP", "22"),
    "RDP": ("TCP", "3389"),
    "DNS-UDP": ("UDP", "53"),
    "DNS-TCP": ("TCP", "53"),
    "NTP": ("UDP", "123"),
    "LDAP": ("TCP", "389"),
    "LDAPS": ("TCP", "636"),
    "KERBEROS": ("TCP", "88"),
    "SMB": ("TCP", "445"),
    "SNMP": ("UDP", "161"),
    "SYSLOG": ("UDP", "514"),
    "SMTP": ("TCP", "25"),
    "API": ("TCP", "9443"),
    "MQ": ("TCP", "5671"),
    "REDIS": ("TCP", "6379"),
    "ELASTIC": ("TCP", "9200"),
    "BACKUP": ("TCP", "10000"),
}
DB_SERVICES = ("MSSQL", "ORACLE", "POSTGRES", "MYSQL")
WEB_SERVICES = ("HTTPS", "ALT-HTTPS", "API", "HTTP")


@dataclass
class Obj:
    name: str
    resource: str  # FMC resource: hosts, networks, ranges, fqdns, protocolportobjects, ...
    value: str | None = None  # address / range / fqdn / "PROTO/port"
    members: list[str] = field(default_factory=list)  # groups: member names
    depth: int = 0  # groups: creation wave (members first)
    tier: str | None = None


@dataclass
class RuleSpec:
    name: str
    category: str
    action: str = "ALLOW"
    src: list[str] = field(default_factory=list)
    dst: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    src_literals: list[str] = field(default_factory=list)
    dst_literals: list[str] = field(default_factory=list)
    enabled: bool = True
    ips: str | None = None
    dst_dynamic: list[str] = field(default_factory=list)  # dynamic object names
    pattern: str = "clean"  # what the analysis should find (for the report)


@dataclass
class Scenario:
    objects: dict[str, Obj] = field(default_factory=dict)
    rules: list[RuleSpec] = field(default_factory=list)
    assets: list[dict[str, str]] = field(default_factory=list)  # doctrine CSV rows
    # build_policies: access policy name -> its rules; dynamic object -> its mappings.
    policies: dict[str, list[RuleSpec]] = field(default_factory=dict)
    dynamic: dict[str, list[str]] = field(default_factory=dict)


class _Gen:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)  # noqa: S311  # nosec B311 - seeded lab data, never secrets
        self.sc = Scenario()
        self.servers: dict[str, list[str]] = {t: [] for t in TIERS}  # tier -> host names
        self.system_nets: dict[str, list[tuple[str, str]]] = {t: [] for t in TIERS}  # (sys, net)
        self.system_groups: dict[str, list[str]] = {t: [] for t in TIERS}
        self.user_nets: list[str] = []
        self.user_groups: list[str] = []
        self.paws: list[str] = []
        self.dmz: list[str] = []
        self.partners: list[str] = []
        self.dups: dict[str, str] = {}  # duplicate -> original

    # ---- objects

    def add(self, obj: Obj) -> str:
        if obj.name in self.sc.objects:
            return obj.name
        self.sc.objects[obj.name] = obj
        return obj.name

    def host(self, name: str, ip: str, tier: str | None = None) -> str:
        return self.add(Obj(name, "hosts", ip, tier=tier))

    def network(self, name: str, cidr: str, tier: str | None = None) -> str:
        return self.add(Obj(name, "networks", cidr, tier=tier))

    def group(self, name: str, members: list[str]) -> str:
        depth = 1 + max(
            (
                self.sc.objects[m].depth
                for m in members
                if self.sc.objects[m].resource == "networkgroups"
            ),
            default=0,
        )
        return self.add(
            Obj(name, "networkgroups", members=list(dict.fromkeys(members)), depth=depth)
        )

    def address_plan(self, target_hosts: int) -> None:
        core = {"DNS": 4, "DC": 4, "NTP": 2, "PKI": 2, "SYSLOG": 2, "RADIUS": 2, "PROXY": 2}
        n = 10
        for role, count in core.items():
            members = []
            for i in range(1, count + 1):
                members.append(self.host(f"H_{role}_{i:02d}", f"10.0.0.{n}", "CORE"))
                self.servers["CORE"].append(members[-1])
                n += 1
            self.system_groups["CORE"].append(self.group(f"GRP_SVC_{role}", members))
            self.sc.assets += [
                {
                    "network": f"{self.sc.objects[m].value}",
                    "system": f"{role}",
                    "tier": "CORE",
                    "system_type": "Infra",
                    "asset": "CORE-SERVICES",
                    "asset_kind": "system",
                }
                for m in members
            ]
        per_tier = {"GOLD": 0.12, "SILVER": 0.38, "BRONZE": 0.38}
        bases = {"GOLD": (20, GOLD_SYSTEMS), "SILVER": (30, None), "BRONZE": (40, None)}
        for tier, share in per_tier.items():
            second, names = bases[tier]
            systems = list(names) if names else [f"{tier[:3]}-APP{i:02d}" for i in range(1, 41)]
            hosts_per = max(3, int(target_hosts * share) // len(systems))
            for s_i, system in enumerate(systems):
                net = f"10.{second}.{s_i}.0/24"
                net_name = self.network(f"NET_{system}", net, tier)
                self.system_nets[tier].append((system, net_name))
                members = [net_name] if self.rng.random() < 0.3 else []
                for h in range(hosts_per):
                    ip = f"10.{second}.{s_i}.{10 + h}"
                    name = self.host(f"H_{system}_{h + 1:02d}", ip, tier)
                    self.servers[tier].append(name)
                    members.append(name)
                self.system_groups[tier].append(self.group(f"GRP_SYS_{system}", members))
                self.sc.assets.append(
                    {
                        "network": net,
                        "system": system,
                        "tier": tier,
                        "system_type": "DB" if tier == "GOLD" else "App",
                        "asset": system,
                        "asset_kind": "system",
                    }
                )
        for d_i, dept in enumerate(DEPARTMENTS):
            for site in range(1, 5):
                cidr = f"10.{100 + site}.{d_i * 4}.0/22"
                self.user_nets.append(self.network(f"NET_USERS_{dept}_S{site}", cidr, "USERS"))
                self.sc.assets.append(
                    {
                        "network": cidr,
                        "system": f"{dept}-USERS",
                        "tier": "USERS",
                        "user_type": dept,
                        "asset": f"{dept}-USERS",
                        "asset_kind": "user_segment",
                    }
                )
            group = self.group(f"GRP_USERS_{dept}", self.user_nets[-4:])
            self.user_groups.append(group)
        for i in range(1, 61):
            self.paws.append(self.host(f"H_PAW_{i:03d}", f"10.105.0.{i + 10}", "USERS"))
        for i in range(1, 21):
            cidr = f"172.16.{i}.0/24"
            self.dmz.append(self.network(f"NET_DMZ_WEB{i:02d}", cidr))
            self.sc.assets.append(
                {
                    "network": cidr,
                    "system": f"DMZ-WEB{i:02d}",
                    "tier": "BRONZE",
                    "system_type": "Web",
                    "asset": "DMZ",
                    "asset_kind": "system",
                }
            )
            for h in range(1, 11):
                self.dmz.append(self.host(f"H_DMZ_WEB{i:02d}_{h:02d}", f"172.16.{i}.{10 + h}"))
        for i in range(1, 41):
            self.partners.append(self.network(f"NET_PARTNER_{i:02d}", f"198.51.{i}.0/24"))

    def services(self) -> None:
        for name, (proto, port) in SERVICES.items():
            self.add(Obj(f"SVC_{name}", "protocolportobjects", f"{proto}/{port}"))
            # The same port under the names different admins gave it (duplicates).
            self.add(Obj(f"{proto.lower()}-{port}", "protocolportobjects", f"{proto}/{port}"))
            if self.rng.random() < 0.5:
                self.add(Obj(f"{proto}_{port}_{name}", "protocolportobjects", f"{proto}/{port}"))
        for app_port in range(20000, 20000 + 300):
            self.add(Obj(f"APP_TCP_{app_port}", "protocolportobjects", f"TCP/{app_port}"))
        self.add(Obj("TCP_HIGH_PORTS", "protocolportobjects", "TCP/1024-65535"))
        self.add(Obj("UDP_HIGH_PORTS", "protocolportobjects", "UDP/1024-65535"))
        self.add(Obj("TCP_ALL", "protocolportobjects", "TCP/1-65535"))
        groups = {
            "PG_WEB": ["SVC_HTTPS", "SVC_HTTP", "SVC_ALT-HTTPS"],
            "PG_DB": [f"SVC_{s}" for s in DB_SERVICES],
            "PG_AD": ["SVC_LDAP", "SVC_LDAPS", "SVC_KERBEROS", "SVC_DNS-TCP"],
            "PG_DNS": ["SVC_DNS-UDP", "SVC_DNS-TCP"],
            "PG_ADMIN": ["SVC_SSH", "SVC_RDP"],
            "PG_MON": ["SVC_SNMP", "SVC_SYSLOG"],
        }
        for name, members in groups.items():
            self.add(Obj(name, "portobjectgroups", members=members, depth=1))
        apps = [n for n in self.sc.objects if n.startswith("APP_TCP_")]
        for i in range(0, len(apps), 6):
            self.add(
                Obj(f"PG_APP_{i // 6:03d}", "portobjectgroups", members=apps[i : i + 6], depth=1)
            )

    def mess_objects(self, target_total: int) -> None:
        # Duplicates of servers named by address (the classic mess).
        for name in self.rng.sample(
            self.servers["SILVER"] + self.servers["GOLD"], k=min(900, len(self.servers["SILVER"]))
        ):
            ip = self.sc.objects[name].value or ""
            dup = (
                self.host(f"H_{ip}", ip)
                if self.rng.random() < 0.5
                else self.host(f"srv-{ip.replace('.', '-')}", ip)
            )
            self.dups[dup] = name
        # Networks named by address, sub-splits and supernets.
        for tier in ("GOLD", "SILVER", "BRONZE"):
            for system, net in self.system_nets[tier]:
                cidr = self.sc.objects[net].value or ""
                if self.rng.random() < 0.4:
                    self.dups[self.network(f"NET_{cidr.replace('/', '_')}", cidr)] = net
                base = ipaddress.IPv4Network(cidr)
                for sub in list(base.subnets(new_prefix=26))[: self.rng.randint(1, 4)]:
                    self.network(
                        f"NET_{system}_{str(sub.network_address).split('.')[-1]}_26", str(sub)
                    )
        self.network("NET_ALL_GOLD", "10.20.0.0/16")
        self.network("NET_ALL_SILVER", "10.30.0.0/16")
        self.network("NET_ALL_SERVERS_10", "10.0.0.0/8")
        # Ranges and FQDNs.
        for i in range(1, 201):
            self.add(
                Obj(
                    f"RNG_LEGACY_{i:03d}",
                    "ranges",
                    f"10.{40 + i % 20}.{i % 200}.10-10.{40 + i % 20}.{i % 200}.60",
                )
            )
        for i in range(1, 201):
            self.add(Obj(f"FQDN_PARTNER_{i:03d}", "fqdns", f"api{i}.partner{i % 40}.example"))
        # Role groups by tier, mixed-tier groups, duplicate groups, chains, unused groups.
        for tier in ("GOLD", "SILVER", "BRONZE"):
            self.system_groups[tier].append(self.group(f"GRP_SRV_{tier}", self.system_groups[tier]))
        for i in range(1, 61):
            g = self.rng.choice(self.system_groups["GOLD"][:-1])
            s = self.rng.choice(self.system_groups["SILVER"][:-1])
            self.group(f"GRP_PROJECT_{i:03d}", [g, s])  # mixes tiers
        for i, name in enumerate(self.system_groups["SILVER"][:40]):
            self.group(f"GRP_{10 + i}.30.0.0", [name])  # address-named role group
        for c in range(1, 41):
            leaf = self.rng.choice(self.servers["GOLD"])
            below = leaf
            for level in range(1, self.rng.randint(4, 8) + 1):
                members = [below] + ([leaf] if level == 3 else [])  # redundant member at level 3
                below = self.group(f"GRP_CHAIN{c:02d}_L{level}", members)
        for i in range(1, 201):
            sample = self.rng.sample(self.servers["BRONZE"], k=3)
            self.group(f"GRP_OLD_UNUSED_{i:03d}", sample)
        for i in range(1, 101):
            original = self.rng.choice(self.system_groups["SILVER"][:-1])
            self.group(f"{original}_COPY{i:02d}", list(self.sc.objects[original].members))
        # Fill up to the requested total with unused legacy hosts.
        i = 1
        while len(self.sc.objects) < target_total:
            self.host(
                f"H_LEGACY_{i:05d}", f"10.{60 + (i // 60000)}.{(i // 250) % 250}.{i % 250 + 1}"
            )
            i += 1

    # ---- rules

    def pick(self, items: list[str], k: int = 1) -> list[str]:
        return self.rng.sample(items, k=min(k, len(items)))

    def rulebase(self, total: int, extras: bool = False) -> None:
        rules = self.sc.rules
        counter = 0

        def rule(category: str, pattern: str, **kw: Any) -> RuleSpec:
            nonlocal counter
            counter += 1
            r = RuleSpec(
                name=kw.pop("name", f"R{counter:04d}_{pattern.upper()}"),
                category=category,
                pattern=pattern,
                **kw,
            )
            rules.append(r)
            return r

        gold, silver, bronze = (self.system_groups[t][:-1] for t in ("GOLD", "SILVER", "BRONZE"))
        core = self.system_groups["CORE"]
        weights = [
            ("users_apps", 18),
            ("apps_db", 10),
            ("core", 4),
            ("admin", 6),
            ("dmz", 4),
            ("partner", 3),
            ("duplicate", 8),
            ("shadowed", 8),
            ("merge", 10),
            ("split", 5),
            ("wide", 4),
            ("literal", 4),
            ("tier_skip", 4),
            ("trust", 3),
            ("redundant", 3),
            ("block", 3),
            ("disabled", 3),
        ]
        if extras:
            weights += [("dynamic", 1), ("bogon", 1)]
        names = [w[0] for w in weights]
        probs = [w[1] for w in weights]
        while len(rules) < total - 3:
            kind = self.rng.choices(names, probs)[0]
            if kind == "users_apps":
                rule(
                    "Users-to-Apps",
                    "clean",
                    src=self.pick(self.user_groups),
                    dst=self.pick(silver),
                    ports=[f"SVC_{self.rng.choice(WEB_SERVICES)}"],
                )
            elif kind == "apps_db":
                gold_dst = self.pick(gold)
                rule(
                    "Apps-to-DB",
                    "gold_without_ips" if self.rng.random() < 0.5 else "clean",
                    src=self.pick(silver),
                    dst=gold_dst,
                    ports=[f"SVC_{self.rng.choice(DB_SERVICES)}"],
                    ips=None if self.rng.random() < 0.5 else "Balanced Security and Connectivity",
                )
            elif kind == "core":
                svc = self.rng.choice(["PG_DNS", "PG_AD", "SVC_NTP"])
                rule(
                    "Infra-Core",
                    "clean",
                    src=self.pick(self.user_groups + silver, 2),
                    dst=self.pick(core),
                    ports=[svc],
                )
            elif kind == "admin":
                rule(
                    "Admin-Access",
                    "clean",
                    src=self.pick(self.paws, 2),
                    dst=self.pick(gold + silver),
                    ports=self.pick(["SVC_SSH", "SVC_RDP", "PG_ADMIN"]),
                )
            elif kind == "dmz":
                rule(
                    "DMZ-Inbound",
                    "clean",
                    src=self.pick([d for d in self.dmz if d.startswith("NET_")]),
                    dst=self.pick(silver),
                    ports=["SVC_API"],
                )
            elif kind == "partner":
                rule(
                    "Partners",
                    "clean",
                    src=self.pick(self.partners),
                    dst=self.pick([d for d in self.dmz if d.startswith("NET_")]),
                    ports=["SVC_HTTPS"],
                )
            elif kind == "duplicate" and rules:
                base = self.rng.choice(rules)
                rule(
                    base.category,
                    "duplicate",
                    src=list(base.src),
                    dst=list(base.dst),
                    ports=list(base.ports),
                    src_literals=list(base.src_literals),
                    dst_literals=list(base.dst_literals),
                    action=base.action,
                    name=f"{base.name}_COPY{counter:04d}",
                )
            elif kind == "shadowed":
                group = self.rng.choice(gold + silver)
                wide = rule(
                    "Projects-2019",
                    "shadowing",
                    src=self.pick(self.user_groups),
                    dst=[group],
                    ports=["TCP_HIGH_PORTS"],
                )
                members = [
                    m
                    for m in self.sc.objects[group].members
                    if self.sc.objects[m].resource == "hosts"
                ]
                if members:
                    rule(
                        "Projects-2021",
                        "shadowed",
                        src=list(wide.src),
                        dst=self.pick(members),
                        ports=[f"APP_TCP_{self.rng.randint(20000, 20299)}"],
                    )
            elif kind == "merge":
                targets, web = self.pick(silver), [f"SVC_{self.rng.choice(WEB_SERVICES)}"]
                category = self.rng.choice(("Projects-2021", "Projects-2023", "Migration"))
                for source in self.pick(self.user_groups, self.rng.randint(2, 4)):
                    rule(category, "merge", src=[source], dst=list(targets), ports=list(web))
            elif kind == "split":
                rule(
                    "Migration",
                    "split",
                    src=self.pick(self.user_groups),
                    dst=self.pick(gold) + self.pick(silver) + self.pick(bronze),
                    ports=["SVC_HTTPS", "SVC_MSSQL"],
                )
            elif kind == "wide":
                rule(
                    "Temp-Exceptions",
                    "wide_ports",
                    src=self.pick(self.user_groups),
                    dst=self.pick(bronze + silver),
                    ports=self.pick(["TCP_HIGH_PORTS", "TCP_ALL", "UDP_HIGH_PORTS"]),
                )
            elif kind == "literal":
                net = self.rng.choice(self.system_nets["SILVER"])[1]
                rule(
                    "Vendors",
                    "literal",
                    src_literals=[f"203.0.113.{self.rng.randint(1, 250)}"],
                    dst_literals=[self.sc.objects[net].value or "10.30.0.0/24"],
                    ports=["SVC_HTTPS"],
                )
            elif kind == "tier_skip":
                rule(
                    "Legacy",
                    "tier_skip",
                    src=self.pick(bronze + self.user_groups),
                    dst=self.pick(gold),
                    ports=[f"SVC_{self.rng.choice(DB_SERVICES)}"],
                )
            elif kind == "trust":
                rule(
                    "Backup",
                    "trust",
                    action="TRUST",
                    src=self.pick(silver),
                    dst=self.pick(gold),
                    ports=["SVC_BACKUP"],
                )
            elif kind == "redundant":
                chains = [
                    n for n in self.sc.objects if n.startswith("GRP_CHAIN") and n.endswith("_L4")
                ]
                top = self.rng.choice(chains)
                inner = list(self.sc.objects[top].members)
                rule(
                    "Monitoring",
                    "redundant",
                    src=self.pick(silver),
                    dst=[top, *inner],
                    ports=["PG_MON"],
                )
            elif kind == "block":
                rule(
                    "Legacy",
                    "block",
                    action="BLOCK",
                    src=self.pick(self.partners),
                    dst=self.pick(gold),
                )
            elif kind == "dynamic" and self.sc.dynamic:
                rule(
                    "Projects-2023",
                    "dynamic",
                    src=self.pick(self.user_groups),
                    dst_dynamic=self.pick(sorted(self.sc.dynamic)),
                    ports=["SVC_HTTPS"],
                )
            elif kind == "bogon":
                rule(
                    "Partners",
                    "prefilter_blocked",
                    src_literals=[f"0.{self.rng.randint(1, 250)}.0.0/16"],
                    dst=self.pick([d for d in self.dmz if d.startswith("NET_")]),
                    ports=["SVC_HTTPS"],
                )
            elif kind == "disabled":
                rule(
                    "Legacy",
                    "disabled",
                    src=self.pick(self.user_groups),
                    dst=self.pick(bronze),
                    enabled=False,
                    ports=["SVC_HTTP"],
                )
        # A few "temporary" broad rules near the end (they shadow little but are red).
        rule("Temp-Exceptions", "any_destination", src=self.pick(self.paws), ports=["PG_ADMIN"])
        rule("Temp-Exceptions", "any_source", dst=self.pick(bronze), ports=["SVC_HTTPS"])
        rule("Temp-Exceptions", "any_any", name="TEMP_ANY_ANY_DO_NOT_USE")
        order = {c: i for i, c in enumerate(CATEGORIES)}
        rules.sort(key=lambda r: order[r.category])  # categories group the rulebase (stable)

    def declare_services(self) -> None:
        """Server assets declare the ports they serve (what port tightening relies on)."""
        for row in self.sc.assets:
            if row.get("asset_kind") != "system":
                continue
            if row["tier"] == "GOLD":
                row["ports"] = "TCP 1433, TCP 1521, TCP 5432, TCP 3306, TCP 10000"
            elif row["tier"] in ("SILVER", "BRONZE"):
                row["ports"] = "TCP 443, TCP 80, TCP 8443, TCP 9443"

    def dynamic_objects(self, count: int = 12) -> None:
        for i in range(1, count + 1):
            self.sc.dynamic[f"DYN_K8S_NS{i:02d}"] = [
                f"10.{120 + i}.{n}.0/24" for n in range(self.rng.randint(1, 4))
            ]


def build_policies(
    seed: int = 11,
    names: tuple[str, ...] = ("DF-LAB-DC1", "DF-LAB-DC2", "DF-LAB-BRANCH", "DF-LAB-DMZ"),
    objects: int = 8_000,
    rules: int = 2_000,
) -> Scenario:
    """One object pool, one messy rulebase per access policy (the dry run before production)."""
    gen = _Gen(seed)
    gen.address_plan(target_hosts=int(objects * 0.45))
    gen.services()
    gen.mess_objects(objects)
    gen.declare_services()
    gen.dynamic_objects()
    for name in names:
        gen.sc.rules = []
        gen.rulebase(rules, extras=True)
        gen.sc.policies[name] = gen.sc.rules
    gen.sc.rules = []
    return gen.sc


def build(seed: int = 7, objects: int = 10_000, rules: int = 3_000) -> Scenario:
    gen = _Gen(seed)
    gen.address_plan(target_hosts=int(objects * 0.45))
    gen.services()
    gen.mess_objects(objects)
    gen.rulebase(rules)
    return gen.sc
