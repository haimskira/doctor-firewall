"""Deterministic generator of a realistic — deliberately messy — FMC configuration.

It models what the system must cope with in a real estate: tiered servers (CORE /
GOLD / SILVER / BRONZE), user networks, duplicate objects under different names,
deep and cyclic group nesting, duplicate membership, inline literals, any-any rules,
bronze->gold access, identical rules, disabled rules, zero-hit rules, SGTs, dynamic
objects, applications, IPS/file policies, interfaces, static routes and BGP.

Payload shapes follow the FMC 10.1 REST API (``expanded=true`` forms).
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from functools import partial
from typing import Any

Json = dict[str, Any]

CATEGORIES = ("DC-Inbound", "Users", "Infra")


def _id(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _ref(obj: Json) -> Json:
    return {"id": obj["id"], "name": obj["name"], "type": obj["type"]}


@dataclass
class FmcData:
    objects: dict[str, list[Json]] = field(default_factory=dict)  # FMC resource name -> items
    # Not firewall objects (the collector does not pull them); used by rule writes.
    variable_sets: list[Json] = field(default_factory=list)
    devices: list[Json] = field(default_factory=list)
    ha_pairs: list[Json] = field(default_factory=list)
    policies: list[Json] = field(default_factory=list)
    categories: dict[str, list[Json]] = field(default_factory=dict)  # policy id -> categories
    rules: dict[str, list[Json]] = field(default_factory=dict)  # policy id -> ordered rules
    assignments: list[Json] = field(default_factory=list)
    interfaces: dict[str, dict[str, list[Json]]] = field(
        default_factory=dict
    )  # dev -> kind -> items
    static_routes: dict[str, list[Json]] = field(default_factory=dict)
    bgp_general: dict[str, list[Json]] = field(default_factory=dict)
    bgp: dict[str, list[Json]] = field(default_factory=dict)
    hitcounts: dict[tuple[str, str], list[Json]] = field(default_factory=dict)  # (policy, dev)
    # Other policy types: resource -> policies, and (resource, policy id, sub) -> rules.
    policy_lists: dict[str, list[Json]] = field(default_factory=dict)
    policy_rules: dict[tuple[str, str, str], list[Json]] = field(default_factory=dict)

    def add_policy(self, resource: str, policy: Json) -> Json:
        self.policy_lists.setdefault(resource, []).append(policy)
        return policy

    def by_id(self) -> dict[str, Json]:
        index: dict[str, Json] = {}
        for items in self.objects.values():
            for item in items:
                index[item["id"]] = item
        return index


def objs(*items: Json) -> Json:
    return {"objects": [_ref(i) for i in items]}


def _add_rule(
    rules: list[Json], rng: random.Random, section: str, category: str, **fields: Any
) -> Json:
    r: Json = {
        "id": _id(rng),
        "type": "AccessRule",
        "enabled": True,
        "action": "ALLOW",
        "logBegin": False,
        "logEnd": True,
        "sendEventsToFMC": True,
        "metadata": {"section": section, "category": category},
    }
    r.update(fields)
    r.setdefault("name", f"rule-{len(rules) + 1}")
    rules.append(r)
    return r


class _Builder:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)  # noqa: S311 - deterministic test data, not crypto
        self.data = FmcData()

    def obj(self, resource: str, type_: str, name: str, **fields: Any) -> Json:
        item: Json = {
            "id": _id(self.rng),
            "name": name,
            "type": type_,
            "overridable": False,
            "description": fields.pop("description", " "),
        }
        item.update(fields)
        self.data.objects.setdefault(resource, []).append(item)
        return item

    def host(self, name: str, ip: str) -> Json:
        return self.obj("hosts", "Host", name, value=ip)

    def net(self, name: str, cidr: str) -> Json:
        return self.obj("networks", "Network", name, value=cidr)

    def group(self, name: str, members: list[Json], literals: list[Json] | None = None) -> Json:
        fields: Json = {"objects": [_ref(m) for m in members]}
        if literals:
            fields["literals"] = literals
        return self.obj("networkgroups", "NetworkGroup", name, **fields)

    def port(self, name: str, protocol: str, port: str | None) -> Json:
        fields: Json = {"protocol": protocol}
        if port is not None:
            fields["port"] = port
        return self.obj("protocolportobjects", "ProtocolPortObject", name, **fields)


def generate(clusters: int = 3, rules_per_policy: int = 200, seed: int = 1) -> FmcData:
    b = _Builder(seed)
    rng = b.rng

    # ---------------- objects ----------------
    dns1 = b.host("H_DNS1", "10.0.0.53")
    dns1_dup = b.host("dns-primary", "10.0.0.53")  # duplicate value, different name
    dc1 = b.host("H_DC1", "10.0.0.10")
    dc2 = b.host("H_DC2", "10.0.0.11")
    ntp = b.host("H_NTP", "10.0.0.123")
    gold_db = [b.host(f"H_GOLD_DB{i}", f"10.20.5.{10 + i}") for i in range(1, 5)]
    gold_net = b.net("NET_GOLD_DB", "10.20.5.0/24")
    gold_net_dup = b.net("net-10.20.5.0", "10.20.5.0/24")  # duplicate network
    silver_net = b.net("NET_SILVER_APP", "10.30.0.0/16")
    bronze_net = b.net("NET_BRONZE_DEV", "10.40.0.0/16")
    users_fin = b.net("NET_USERS_FIN", "10.100.10.0/24")
    users_it = b.net("NET_USERS_IT", "10.100.20.0/24")
    users_gen = b.net("NET_USERS_GENERAL", "10.100.0.0/16")
    dba_paw = b.host("H_DBA_PAW", "10.100.20.50")
    rng_obj = b.obj("ranges", "Range", "RANGE_SCANNERS", value="10.50.0.10-10.50.0.20")
    dmz_web = b.host("H_DMZ_WEB", "172.16.50.10")  # referenced only by NAT
    dmz_web_public = b.host("H_DMZ_WEB_PUBLIC", "198.51.100.10")  # referenced only by NAT
    nat_pool = b.obj("ranges", "Range", "NAT_POOL_OUT", value="198.51.100.100-198.51.100.120")
    fqdn = b.obj(
        "fqdns", "FQDN", "FQDN_UPDATES", value="updates.vendor.example", dnsResolution="IPV4_ONLY"
    )
    any_ipv4 = b.net("any-ipv4", "0.0.0.0/0")
    extra_hosts = [b.host(f"H_SRV_{i:03d}", f"10.30.{i // 250}.{i % 250 + 1}") for i in range(40)]

    grp_core_dns = b.group("GRP_SVC_DNS", [dns1, dns1_dup])
    grp_core_ad = b.group("GRP_SVC_AD", [dc1, dc2])
    b.group("GRP_SVC_NTP", [ntp])
    grp_gold = b.group("GRP_SRV_GOLD", [*gold_db, gold_net])
    grp_users_fin = b.group("GRP_SRC_FIN", [users_fin])
    grp_users_it = b.group("GRP_SRC_IT", [users_it, dba_paw])
    grp_users_all = b.group("GRP_USERS_ALL", [grp_users_fin, grp_users_it, users_gen])
    # Duplicate membership: H_GOLD_DB1 directly and via GRP_SRV_GOLD.
    grp_dc = b.group(
        "GRP_DC_ALL",
        [grp_gold, gold_db[0], silver_net],
        literals=[{"type": "Host", "value": "10.20.9.9"}],
    )
    # Deep nesting chain (depth 6).
    chain_leaf = b.group("GRP_NEST_6", [extra_hosts[0]])
    prev = chain_leaf
    for depth in range(5, 0, -1):
        prev = b.group(f"GRP_NEST_{depth}", [prev, extra_hosts[depth]])
    grp_nest_top = prev
    # Cycle (real FMCs reject this; the analyser must still survive and flag it).
    loop_a = b.group("GRP_LOOP_A", [extra_hosts[10]])
    loop_b = b.group("GRP_LOOP_B", [loop_a, extra_hosts[11]])
    loop_a["objects"].append(_ref(loop_b))
    b.group("GRP_UNUSED", [extra_hosts[20]])  # never referenced
    # Named by address instead of role, and a second group with the same members.
    grp_ip_named = b.group("GRP_10.30.0.0", [silver_net])
    b.group("GRP_WEB_SERVERS", [silver_net])

    tcp443 = b.port("HTTPS", "TCP", "443")
    tcp443_dup = b.port("tcp-443", "TCP", "443")
    tcp1433 = b.port("SVC_TCP1433", "TCP", "1433")
    tcp22 = b.port("SSH", "TCP", "22")
    tcp3389 = b.port("RDP", "TCP", "3389")
    udp53 = b.port("DNS_UDP", "UDP", "53")
    tcp53 = b.port("DNS_TCP", "TCP", "53")
    tcp_hi = b.port("TCP_HIGH", "TCP", "1024-65535")
    b.port("ANY_TCP", "TCP", None)
    ldap = b.port("LDAP", "TCP", "389")
    kerb = b.port("KERBEROS", "TCP", "88")
    pg_web = b.obj(
        "portobjectgroups",
        "PortObjectGroup",
        "GRP_PORTS_WEB",
        objects=[_ref(tcp443), _ref(tcp443_dup), _ref(b.port("HTTP", "TCP", "80"))],
    )
    pg_ad = b.obj(
        "portobjectgroups",
        "PortObjectGroup",
        "GRP_PORTS_AD",
        objects=[_ref(ldap), _ref(kerb), _ref(tcp53), _ref(udp53)],
    )
    pg_admin = b.obj(
        "portobjectgroups",
        "PortObjectGroup",
        "GRP_PORTS_ADMIN",
        objects=[_ref(tcp22), _ref(tcp3389)],
    )
    b.obj("icmpv4objects", "ICMPV4Object", "ICMP_ECHO", icmpType="8", code=0)

    zones = {
        z: b.obj("securityzones", "SecurityZone", z, interfaceMode="ROUTED", interfaces=[])
        for z in ("inside", "outside", "dmz", "dc", "users")
    }
    sgt_fin = b.obj("isesecuritygrouptags", "ISESecurityGroupTag", "SGT_FIN_USERS", tag="10")
    sgt_bad = b.obj("securitygrouptags", "SecurityGroupTag", "SGT_QUARANTINE", tag="999")
    dyn = b.obj("dynamicobjects", "DynamicObject", "DYN_K8S_PODS", objectType="IP")
    url = b.obj("urls", "Url", "URL_PARTNER", url="https://partner.example")

    apps = [
        {"id": _id(rng), "name": name, "type": "Application"}
        for name in ("HTTP", "HTTPS", "SSH", "MS-SQL", "LDAP", "DNS", "RDP")
    ]
    ips = {"id": _id(rng), "name": "Balanced Security and Connectivity", "type": "IntrusionPolicy"}
    ips_max = {"id": _id(rng), "name": "Maximum Detection", "type": "IntrusionPolicy"}
    file_pol = {"id": _id(rng), "name": "Block Malware", "type": "FilePolicy"}

    data = b.data
    data.add_policy(
        "intrusionpolicies",
        {
            **ips,
            "inspectionMode": "PREVENTION",
            "basePolicy": {"id": _id(rng), "name": "Balanced", "type": "IntrusionPolicy"},
        },
    )
    data.add_policy("intrusionpolicies", {**ips_max, "inspectionMode": "PREVENTION"})
    data.add_policy("filepolicies", dict(file_pol))
    data.add_policy(
        "dnspolicies", {"id": _id(rng), "name": "Default DNS Policy", "type": "DNSPolicy"}
    )
    decrypt = data.add_policy(
        "decryptionpolicies", {"id": _id(rng), "name": "DECRYPT-DC", "type": "DecryptionPolicy"}
    )
    data.policy_rules[("decryptionpolicies", decrypt["id"], "decryptionpolicyrules")] = [
        {
            "id": _id(rng),
            "type": "DecryptionPolicyRule",
            "name": "DND_CORE",
            "enabled": True,
            "action": "DO_NOT_DECRYPT",
            "destinationNetworks": objs(grp_core_ad, grp_core_dns),
        },
        {
            "id": _id(rng),
            "type": "DecryptionPolicyRule",
            "name": "KNOWN_KEY_GOLD",
            "enabled": True,
            "action": "DECRYPT_KNOWN_KEY",
            "destinationNetworks": objs(grp_gold),
            "destinationPorts": objs(tcp443),
        },
        {
            "id": _id(rng),
            "type": "DecryptionPolicyRule",
            "name": "RESIGN_USERS_OUT",
            "enabled": True,
            "action": "DECRYPT_RESIGN",
            "sourceNetworks": objs(grp_users_all),
        },
    ]
    identity = data.add_policy(
        "identitypolicies", {"id": _id(rng), "name": "ID-CORP", "type": "IdentityPolicy"}
    )
    data.policy_rules[("identitypolicies", identity["id"], "identityrules")] = [
        {
            "id": _id(rng),
            "type": "IdentityRule",
            "name": "PASSIVE_USERS",
            "enabled": True,
            "action": "PASSIVE_AUTH",
            "sourceNetworks": objs(users_gen),
        },
        {
            "id": _id(rng),
            "type": "IdentityRule",
            "name": "NO_AUTH_SERVERS",
            "enabled": True,
            "action": "NO_AUTH",
            "sourceNetworks": objs(silver_net, bronze_net),
        },
    ]

    user_sources = [users_fin, users_it, users_gen, grp_users_fin, grp_users_it, grp_users_all]
    server_dests = [
        grp_gold,
        gold_net,
        gold_net_dup,
        silver_net,
        bronze_net,
        grp_dc,
        *gold_db,
        *extra_hosts[:10],
        grp_nest_top,
        rng_obj,
        fqdn,
    ]
    port_choices = [tcp443, tcp443_dup, tcp1433, tcp22, tcp3389, tcp_hi, pg_web, pg_admin]

    # ---------------- devices, HA pairs, policies ----------------
    for c in range(1, clusters + 1):
        name = f"FTD-CL{c:02d}"
        version = "7.7.13" if c % 3 else "10.0.0"
        devs: list[Json] = []
        for role in ("A", "B"):
            devs.append(
                {
                    "id": _id(rng),
                    "name": f"{name}-{role}",
                    "type": "Device",
                    "hostName": f"10.255.{c}.{1 if role == 'A' else 2}",
                    "model": "Cisco Secure Firewall 4215",
                    "sw_version": version,
                    "ftdMode": "ROUTED",
                    "healthStatus": "green",
                }
            )
        policy: Json = {
            "id": _id(rng),
            "name": f"ACP-{name}",
            "type": "AccessPolicy",
            "defaultAction": {
                "action": "BLOCK",
                "logBegin": True,
                "type": "AccessPolicyDefaultAction",
            },
        }
        prefilter = data.add_policy(
            "prefilterpolicies",
            {
                "id": _id(rng),
                "name": f"PF-{name}",
                "type": "PrefilterPolicy",
                "defaultAction": {
                    "action": "ANALYZE_TUNNELS",
                    "type": "PrefilterPolicyDefaultAction",
                },
            },
        )
        policy["prefilterPolicySetting"] = _ref(prefilter)
        data.policy_rules[("prefilterpolicies", prefilter["id"], "prefilterrules")] = [
            {
                "id": _id(rng),
                "type": "PrefilterRule",
                "name": "BLOCK_BOGONS",
                "enabled": True,
                "ruleType": "PREFILTER",
                "action": "BLOCK",
                "sourceNetworks": {
                    "literals": [
                        {"type": "Network", "value": "0.0.0.0/8"},
                        {"type": "Network", "value": "240.0.0.0/4"},
                    ]
                },
            },
            {
                "id": _id(rng),
                "type": "PrefilterRule",
                "name": "FASTPATH_CORE_DNS",
                "enabled": True,
                "ruleType": "PREFILTER",
                "action": "FASTPATH",
                "destinationNetworks": objs(grp_core_dns),
                "destinationPorts": objs(udp53),
            },
            {
                "id": _id(rng),
                "type": "PrefilterRule",
                "name": "ANALYZE_GRE",
                "enabled": True,
                "ruleType": "TUNNEL",
                "action": "ANALYZE",
                "sourceInterfaces": objs(zones["outside"]),
            },
        ]
        nat = data.add_policy(
            "ftdnatpolicies", {"id": _id(rng), "name": f"NAT-{name}", "type": "FTDNatPolicy"}
        )
        data.policy_rules[("ftdnatpolicies", nat["id"], "manualnatrules")] = [
            {
                "id": _id(rng),
                "type": "FTDManualNatRule",
                "natType": "DYNAMIC",
                "section": "BEFORE_AUTO",
                "enabled": True,
                "description": "Users PAT to pool",
                "sourceInterface": _ref(zones["users"]),
                "destinationInterface": _ref(zones["outside"]),
                "originalSource": _ref(users_gen),
                "translatedSource": _ref(nat_pool),
            },
            {
                "id": _id(rng),
                "type": "FTDManualNatRule",
                "natType": "STATIC",
                "section": "AFTER_AUTO",
                "enabled": False,
                "originalSource": _ref(bronze_net),
                "translatedSource": _ref(bronze_net),
                "originalDestination": _ref(grp_gold),
                "translatedDestination": _ref(grp_gold),
            },
        ]
        data.policy_rules[("ftdnatpolicies", nat["id"], "autonatrules")] = [
            {
                "id": _id(rng),
                "type": "FTDAutoNatRule",
                "natType": "STATIC",
                "originalNetwork": _ref(dmz_web),
                "translatedNetwork": _ref(dmz_web_public),
                "sourceInterface": _ref(zones["dmz"]),
                "destinationInterface": _ref(zones["outside"]),
                "serviceProtocol": "TCP",
                "originalPort": 8443,
                "translatedPort": 443,
            },
        ]
        for d in devs:
            d["accessPolicy"] = _ref(policy)
        ha: Json = {
            "id": _id(rng),
            "name": name,
            "type": "DeviceHAPair",
            "primary": _ref(devs[0]),
            "secondary": _ref(devs[1]),
        }
        b.data.devices.extend(devs)
        b.data.ha_pairs.append(ha)
        b.data.policies.append(policy)
        b.data.assignments.append(
            {
                "id": policy["id"],
                "type": "PolicyAssignment",
                "policy": _ref(policy),
                "targets": [_ref(ha)],
            }
        )
        b.data.assignments.append(
            {
                "id": nat["id"],
                "type": "PolicyAssignment",
                "policy": _ref(nat),
                "targets": [_ref(ha)],
            }
        )
        b.data.categories[policy["id"]] = [
            {"id": _id(rng), "name": cat, "type": "Category"} for cat in CATEGORIES
        ]

        rules: list[Json] = []
        rule = partial(_add_rule, rules, rng)

        # Mandatory: doctrine-shaped rules, plus explicit deny at the top.
        rule(
            "Mandatory",
            "--Undefined--",
            name="DENY_QUARANTINE",
            action="BLOCK",
            sourceSecurityGroupTags=objs(sgt_bad),
        )
        rule(
            "Mandatory",
            "Infra",
            name="CORE_DNS",
            sourceNetworks=objs(grp_users_all),
            destinationNetworks=objs(grp_core_dns),
            destinationPorts=objs(udp53, tcp53),
        )
        rule(
            "Mandatory",
            "Infra",
            name="CORE_AD",
            sourceNetworks=objs(grp_users_all),
            destinationNetworks=objs(grp_core_ad),
            destinationPorts=objs(pg_ad),
        )
        rule(
            "Mandatory",
            "DC-Inbound",
            name="FIN-APP_TO_GOLD-DB_SQL",
            sourceZones=objs(zones["users"]),
            destinationZones=objs(zones["dc"]),
            sourceNetworks=objs(grp_users_fin),
            destinationNetworks=objs(grp_gold),
            destinationPorts=objs(tcp1433),
            ipsPolicy=ips_max,
            filePolicy=file_pol,
            sourceSecurityGroupTags=objs(sgt_fin),
        )
        rule(
            "Mandatory",
            "DC-Inbound",
            name="DBA-PAW_TO_GOLD-DB_ADMIN",
            sourceNetworks=objs(dba_paw),
            destinationNetworks=objs(grp_gold),
            destinationPorts=objs(pg_admin),
            ipsPolicy=ips_max,
        )
        # The messy bulk.
        for i in range(max(0, rules_per_policy - 10)):
            section = "Mandatory" if i < rules_per_policy // 2 else "Default"
            category = rng.choice(CATEGORIES) if section == "Mandatory" else "--Undefined--"
            fields: Json = {"name": f"R{c:02d}-{i:05d}"}
            if rng.random() < 0.85:
                fields["sourceNetworks"] = objs(*rng.sample(user_sources, rng.randint(1, 2)))
            if rng.random() < 0.9:
                fields["destinationNetworks"] = objs(*rng.sample(server_dests, rng.randint(1, 3)))
            if rng.random() < 0.8:
                fields["destinationPorts"] = objs(*rng.sample(port_choices, rng.randint(1, 2)))
            if rng.random() < 0.15:
                fields.setdefault("sourceNetworks", {"objects": []})["literals"] = [
                    {"type": "Host", "value": f"192.168.{rng.randint(0, 9)}.{rng.randint(1, 254)}"}
                ]
            if rng.random() < 0.08:
                fields.setdefault("destinationPorts", {"objects": []})["literals"] = [
                    {
                        "type": "PortLiteral",
                        "port": str(rng.choice([8080, 8443, 5432])),
                        "protocol": "6",
                    }
                ]
            if rng.random() < 0.2:
                fields["applications"] = {"applications": rng.sample(apps, rng.randint(1, 2))}
            if rng.random() < 0.3:
                fields["sourceZones"] = objs(rng.choice([zones["users"], zones["inside"]]))
                fields["destinationZones"] = objs(rng.choice([zones["dc"], zones["dmz"]]))
            if rng.random() < 0.05:
                fields["destinationDynamicObjects"] = objs(dyn)
            if rng.random() < 0.05:
                fields["urls"] = {"objects": [_ref(url)]}
            if rng.random() < 0.3:
                fields["ipsPolicy"] = rng.choice([ips, ips_max])
            if rng.random() < 0.07:
                fields["enabled"] = False
            if rng.random() < 0.05:
                fields["action"] = rng.choice(["BLOCK", "TRUST", "MONITOR"])
            rule(section, category, **fields)
            if rng.random() < 0.03:  # identical duplicate under another name
                dup = {k: v for k, v in fields.items() if k != "name"}
                rule(section, category, name=f"{fields['name']}-copy", **dup)
        # Phase-3 scenarios: adjacent rules differing only by source (merge), one rule
        # spanning two tiers (split), and "any" source behind a zone (tighten).
        for src_group, rule_name in (
            (grp_users_fin, "WEB_FIN_USERS"),
            (grp_users_it, "WEB_IT_USERS"),
        ):
            rule(
                "Default",
                "--Undefined--",
                name=rule_name,
                sourceNetworks=objs(src_group),
                destinationNetworks=objs(grp_ip_named),
                destinationPorts=objs(pg_web),
            )
        rule(
            "Default",
            "--Undefined--",
            name="MIXED_TIERS_SQL",
            sourceNetworks=objs(users_fin),
            destinationNetworks=objs(gold_net, silver_net),
            destinationPorts=objs(tcp1433),
        )
        rule(
            "Default",
            "--Undefined--",
            name="USERS_ZONE_TO_GOLD",
            sourceZones=objs(zones["users"]),
            destinationNetworks=objs(gold_db[1]),
            destinationPorts=objs(tcp1433),
        )
        # Bronze -> gold and any-any: classic violations.
        rule(
            "Default",
            "--Undefined--",
            name="TEMP_DEV_TO_DB",
            sourceNetworks=objs(bronze_net),
            destinationNetworks=objs(grp_gold),
        )
        rule("Default", "--Undefined--", name="ANY_ANY_TEMP")
        rule(
            "Default",
            "--Undefined--",
            name="NESTED_LOOP",
            sourceNetworks=objs(loop_b),
            destinationNetworks=objs(grp_dc),
            destinationPorts=objs(pg_web),
        )
        rule(
            "Default", "--Undefined--", name="EXPLICIT_DEFAULT_DENY", action="BLOCK", logBegin=True
        )

        for index, r in enumerate(rules, start=1):
            r["metadata"]["ruleIndex"] = index
        b.data.rules[policy["id"]] = rules

        # Hit counts per device of the pair (active unit only gets hits).
        for d, active in ((devs[0], True), (devs[1], False)):
            b.data.hitcounts[(policy["id"], d["id"])] = [
                {
                    "type": "HitCount",
                    # About one rule in five never hit (dead), as in a typical estate.
                    "hitCount": (
                        (0 if rng.random() < 0.2 else rng.randint(1, 10_000_000)) if active else 0
                    ),
                    "firstHitTimeStamp": " ",
                    "lastHitTimeStamp": "2026-10-01T10:00:00Z" if active else " ",
                    "rule": {"id": r["id"], "name": r["name"], "type": "AccessRule"},
                    "metadata": {"policy": _ref(policy), "device": _ref(d)},
                }
                for r in rules
            ]

        # Interfaces, routes, BGP — configured on the primary unit.
        primary = devs[0]["id"]
        b.data.interfaces[primary] = {
            "physicalinterfaces": [
                {
                    "id": _id(rng),
                    "type": "PhysicalInterface",
                    "name": f"Ethernet1/{n}",
                    "ifname": ifname,
                    "enabled": True,
                    "mode": "NONE",
                    "MTU": 1500,
                    "securityZone": _ref(zones[zone]),
                    "ipv4": {"static": {"address": addr, "netmask": mask}},
                }
                for n, (ifname, zone, addr, mask) in enumerate(
                    [
                        ("outside", "outside", f"203.0.113.{c}", "24"),
                        ("inside", "inside", f"10.{c}.0.1", "255.255.0.0"),
                        ("dc", "dc", f"10.20.{c}.1", "24"),
                        ("users", "users", f"10.100.{c}.1", "24"),
                    ],
                    start=1,
                )
            ],
            "subinterfaces": [
                {
                    "id": _id(rng),
                    "type": "SubInterface",
                    "name": "Ethernet1/5",
                    "subIntfId": 100,
                    "vlanId": 100,
                    "ifname": "dmz",
                    "enabled": True,
                    "mode": "NONE",
                    "securityZone": _ref(zones["dmz"]),
                    "ipv4": {"static": {"address": f"172.16.{c}.1", "netmask": "24"}},
                },
            ],
        }
        gw = b.host(f"GW_CL{c:02d}_CORE", f"10.{c}.0.254")
        b.data.static_routes[primary] = [
            {
                "id": _id(rng),
                "type": "IPv4StaticRoute",
                "interfaceName": "outside",
                "selectedNetworks": [_ref(any_ipv4)],
                "gateway": {"literal": {"type": "Host", "value": "203.0.113.254"}},
                "metricValue": 1,
                "isTunneled": False,
            },
            {
                "id": _id(rng),
                "type": "IPv4StaticRoute",
                "interfaceName": "dc",
                "selectedNetworks": [_ref(gold_net), _ref(silver_net)],
                "gateway": {"object": _ref(gw)},
                "metricValue": 1,
                "isTunneled": False,
            },
            {
                "id": _id(rng),
                "type": "IPv4StaticRoute",
                "interfaceName": "users",
                "selectedNetworks": [_ref(users_gen)],
                "gateway": {"literal": {"type": "Host", "value": f"10.100.{c}.254"}},
                "metricValue": 10,
                "isTunneled": False,
            },
        ]
        b.data.bgp_general[primary] = [
            {
                "id": _id(rng),
                "type": "BGPGeneralSetting",
                "name": "AsaBGPGeneralTable",
                "asNumber": str(65000 + c),
                "routerId": "AUTOMATIC",
            }
        ]
        b.data.bgp[primary] = [
            {
                "id": _id(rng),
                "type": "bgp",
                "name": "bgp",
                "addressFamilyIPv4": {
                    "neighbors": [
                        {
                            "ipv4Address": "203.0.113.254",
                            "remoteAs": "64512",
                            "neighborGeneral": {"enableAddress": True},
                        },
                    ]
                },
            }
        ]
    # Every FMC has a built-in variable set (used by rules with an intrusion policy).
    # A fixed id keeps the random stream (and so all other seeded data) unchanged.
    variables = {
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "fmc-mock/variableset/Default-Set")),
        "name": "Default-Set",
        "type": "VariableSet",
    }
    b.data.variable_sets.append({**variables, "description": "Default Variable Set"})
    # As the FMC returns them: inspection only on Allow rules, always with a variable set.
    for rules in b.data.rules.values():
        for item in rules:
            if item.get("action") != "ALLOW":
                item.pop("ipsPolicy", None)
                item.pop("filePolicy", None)
            elif "ipsPolicy" in item:
                item["variableSet"] = dict(variables)
    return b.data
