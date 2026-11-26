"""Operational layer for a LAB FMC: what a production estate has around its access policies.

Only for lab systems — it WRITES to the FMC and DEPLOYS::

    python -m app.tools.lab_ops --host firepower --user admin --ca /ca.pem \\
        [network|objects|inspection|decryption|all] --yes-write-to-lab

Built on the HA pair's primary device (the secondary follows on deploy), around the
``lab_scenario`` address plan so that zones and routes resolve the scenario's addresses:

* ``network``: security zones; interfaces — outside, a DMZ, two trunks carrying VLAN
  subinterfaces (CORE / GOLD / SILVER / BRONZE / user sites / PAW / partners / OOB / legacy),
  one interface left "static" with no address (FMC 10.1.1 returns ``{"static": {}}``), one on
  DHCP, IPv6 on the DMZ; static routes for every scenario range and a default route.
  A port-channel is attempted first: FMC refuses it on a virtual FTD (logged, not fatal).
* ``objects``: the object kinds the scenario lacks — VLAN tags and groups, URLs and URL groups,
  time ranges, ICMPv4 / ICMPv6 objects, custom security group tags (SGT), interface groups.
* ``inspection``: the organisation's one intrusion policy (``DF-IPS``, Maximum Detection) plus
  one detection-only policy left as the mess, and a file policy.
* ``decryption``: an internal CA (Decrypt-Resign), generated here and never written to disk, a
  decryption policy whose rules cover every action (Decrypt-Resign on HTTPS included), with and
  without categories, URL / application conditions; an identity policy.

``/work/ops.json`` records what exists (names -> ids); ``lab_dryrun load`` reads it to put
zones, the IPS, file policy, SGT, VLAN, URL and time conditions on part of its rules and links
the decryption / identity policies. The password comes from ``DF_LAB_PASSWORD`` (or stdin).
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.enforce.executor import BatchError, deploy
from app.fmc.adapters import select_adapter
from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError, FmcWriteRejectedError
from app.fmc.probe import server_version
from app.tools.lab_scale import log

MARK = "df-lab-ops"
ZONES = ("OUTSIDE", "CORE", "GOLD", "SILVER", "BRONZE", "USERS", "ADMIN", "DMZ", "PARTNERS", "MGMT")
# physical name -> (ifname, zone, ipv4 {"static"/"dhcp"} or None, ipv6 address or None)
PHYSICAL: dict[str, tuple[str, str | None, dict[str, Any] | None, str | None]] = {
    "GigabitEthernet0/0": (
        "outside",
        "OUTSIDE",
        {"static": {"address": "100.64.0.2", "netmask": "24"}},
        None,
    ),
    "GigabitEthernet0/2": ("", None, None, None),  # trunk: VLAN subinterfaces only
    "GigabitEthernet0/3": ("", None, None, None),  # trunk
    "GigabitEthernet0/4": (
        "dmz",
        "DMZ",
        {"static": {"address": "172.16.0.1", "netmask": "255.255.255.0"}},
        "2001:db8:16::1/64",
    ),
    "GigabitEthernet0/5": ("spare5", None, {"static": {}}, None),  # static, no address yet
    # a second ISP line (HA data interfaces take static addresses only, no DHCP)
    "GigabitEthernet0/6": (
        "isp2",
        "OUTSIDE",
        {"static": {"address": "100.65.0.2", "netmask": "255.255.255.252"}},
        None,
    ),
}
# (parent, subinterface id, ifname, zone, address, prefix); the VLAN tag is the id unless
# VLAN_TAGS says otherwise (lab vSwitch: users-s1 on 1101, gold on 1120).
VLAN_TAGS = {101: 1101, 120: 1120}
SUBINTERFACES = (
    ("GigabitEthernet0/2", 100, "core", "CORE", "10.0.0.1", 24),
    ("GigabitEthernet0/2", 120, "gold", "GOLD", "10.20.255.1", 24),
    ("GigabitEthernet0/2", 130, "silver", "SILVER", "10.30.255.1", 24),
    ("GigabitEthernet0/2", 140, "bronze", "BRONZE", "10.40.255.1", 24),
    ("GigabitEthernet0/2", 101, "users-s1", "USERS", "10.101.255.1", 24),
    ("GigabitEthernet0/2", 102, "users-s2", "USERS", "10.102.255.1", 24),
    ("GigabitEthernet0/2", 103, "users-s3", "USERS", "10.103.255.1", 24),
    ("GigabitEthernet0/2", 104, "users-s4", "USERS", "10.104.255.1", 24),
    ("GigabitEthernet0/2", 105, "paw", "ADMIN", "10.105.0.1", 24),
    ("GigabitEthernet0/3", 150, "partners", "PARTNERS", "192.0.2.1", 24),
    ("GigabitEthernet0/3", 160, "oob", "MGMT", "10.250.0.1", 24),
    ("GigabitEthernet0/3", 170, "legacy", "BRONZE", "10.60.255.1", 24),
)
# (network, interface, gateway); "any-ipv4" is the FMC's built-in default-route object
ROUTES = (
    ("any-ipv4", "outside", "100.64.0.1"),
    ("10.20.0.0/16", "gold", "10.20.255.254"),
    ("10.30.0.0/16", "silver", "10.30.255.254"),
    ("10.40.0.0/16", "bronze", "10.40.255.254"),
    ("10.32.0.0/11", "bronze", "10.40.255.253"),  # the scenario's ranges 10.40-59
    ("10.60.0.0/14", "legacy", "10.60.255.254"),
    ("10.112.0.0/12", "silver", "10.30.255.253"),  # dynamic objects (k8s) 10.120-131
    ("10.101.0.0/16", "users-s1", "10.101.255.254"),
    ("10.102.0.0/16", "users-s2", "10.102.255.254"),
    ("10.103.0.0/16", "users-s3", "10.103.255.254"),
    ("10.104.0.0/16", "users-s4", "10.104.255.254"),
    ("172.16.0.0/16", "dmz", "172.16.0.254"),
    ("198.51.0.0/16", "partners", "192.0.2.254"),
)
# The organisation has one intrusion policy; the second one is the mess (detection only).
IPS_POLICIES = {
    "DF-IPS": ("Maximum Detection", "PREVENTION"),
    "DF-IPS-LEGACY-DETECT": ("Connectivity Over Security", "DETECTION"),
}
SKIP = ("links", "metadata")


class Ops:
    def __init__(self, fmc: FmcSession, work: Path) -> None:
        self.fmc = fmc
        self.adapter = select_adapter("10.1")
        self.path_m = work / "ops.json"
        self.m: dict[str, Any] = {}
        if self.path_m.is_file():
            self.m = json.loads(self.path_m.read_text(encoding="utf-8"))
        for key in ("zones", "objects", "ips", "policies", "interfaces"):
            self.m.setdefault(key, {})

    def save(self) -> None:
        tmp = self.path_m.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.m, indent=1), encoding="utf-8")
        tmp.replace(self.path_m)

    def path(self, suffix: str) -> str:
        return f"/api/fmc_config/v1/domain/{self.fmc.domain_uuid}{suffix}"

    async def all(self, suffix: str, **params: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        query: dict[str, str | int] | None = dict(params) if params else None
        async for _offset, page in self.fmc.iter_pages(self.path(suffix), params=query):
            items.extend(page)
        return items

    async def by_name(self, suffix: str) -> dict[str, dict[str, Any]]:
        return {i["name"]: i for i in await self.all(suffix) if "name" in i}

    async def ensure(
        self, suffix: str, body: dict[str, Any], bucket: str | None = "objects"
    ) -> dict[str, str] | None:
        """POST unless an item of that name exists; record ``{id, type, name}``."""
        existing = (await self.by_name(suffix)).get(body["name"])
        try:
            item = existing or await self.fmc.write_json("POST", self.path(suffix), body)
        except FmcWriteRejectedError as exc:
            log(f"  rejected {suffix} {body['name']}: {exc.description[:200]}")
            return None
        ref = {
            "id": str(item["id"]),
            "type": str(item.get("type", body.get("type"))),
            "name": body["name"],
        }
        if bucket:
            self.m[bucket][body["name"]] = ref
            self.save()
        log(f"  {'exists' if existing else 'created'} {body['name']}")
        return ref

    async def deploy_pending(self, label: str) -> None:
        listing = await self.fmc.get_json(
            self.path("/deployment/deployabledevices"), {"expanded": "true"}
        )
        targets = {
            str(i["device"]["id"]) for i in (listing or {}).get("items", []) if "device" in i
        }
        if not targets:
            log(f"deploy {label}: nothing pending")
            return
        try:
            task = await deploy(
                self.fmc,
                self.adapter,
                self.fmc.domain_uuid,
                targets,
                poll_seconds=15,
                timeout_seconds=3600,
            )
        except BatchError as exc:
            log(f"deploy {label} FAILED: {exc}")
            return
        log(f"deploy {label}: done (task {task})")

    # ------------------------------------------------------------------ network

    async def primary(self) -> str:
        pairs = await self.all("/devicehapairs/ftddevicehapairs", expanded="true")
        if pairs:
            return str(pairs[0]["primary"]["id"])
        devices = await self.all("/devices/devicerecords")
        return str(devices[0]["id"])

    async def network(self) -> None:
        log("zones")
        for name in ZONES:
            await self.ensure(
                "/object/securityzones",
                {
                    "name": f"Z_{name}",
                    "type": "SecurityZone",
                    "interfaceMode": "ROUTED",
                    "description": MARK,
                },
                "zones",
            )
        dev = await self.primary()
        self.m["device"] = dev
        base = f"/devices/devicerecords/{dev}"
        phys = {i["name"]: i for i in await self.all(f"{base}/physicalinterfaces", expanded="true")}
        log("port-channel (FTDv refuses it; production hardware has them)")
        try:
            await self.fmc.write_json(
                "POST",
                self.path(f"{base}/etherchannelinterfaces"),
                {
                    "type": "EtherChannelInterface",
                    "etherChannelId": 1,
                    "mode": "NONE",
                    "enabled": True,
                    "lacpMode": "ACTIVE",
                    "selectedInterfaces": [
                        {"type": "PhysicalInterface", "id": phys[n]["id"], "name": n}
                        for n in ("GigabitEthernet0/2", "GigabitEthernet0/3")
                    ],
                },
            )
        except FmcWriteRejectedError as exc:
            log(f"  port-channel not created: {exc.description[:160]}")
        log("physical interfaces")
        for name, (ifname, zone, ipv4, ipv6) in PHYSICAL.items():
            cur = phys[name]
            body = {k: v for k, v in cur.items() if k not in SKIP}
            body["enabled"] = True
            body["hardware"] = {"duplex": "AUTO", "speed": "AUTO", **(cur.get("hardware") or {})}
            body.pop("ipv4", None)
            body.pop("securityZone", None)
            if ifname:
                body["ifname"] = ifname
            if zone:
                body["securityZone"] = self.zone(zone)
            if ipv4 is not None:
                body["ipv4"] = ipv4
            if ipv6:
                body["ipv6"] = {
                    "enableIPV6": True,
                    "addresses": [{"address": ipv6.split("/")[0], "prefix": ipv6.split("/")[1]}],
                }
            await self.put(f"{base}/physicalinterfaces/{cur['id']}", body, name)
            self.m["interfaces"][name] = cur["id"]
        log("VLAN subinterfaces")
        subs = {
            (i["name"], i.get("subIntfId")): i
            for i in await self.all(f"{base}/subinterfaces", expanded="true")
        }
        for parent, vlan, ifname, zone, address, prefix in SUBINTERFACES:
            body = {
                "type": "SubInterface",
                "name": parent,
                "subIntfId": vlan,
                "vlanId": VLAN_TAGS.get(vlan, vlan),
                "ifname": ifname,
                "enabled": True,
                "MTU": 1500,
                "mode": "NONE",
                "securityZone": self.zone(zone),
                "ipv4": {"static": {"address": address, "netmask": str(prefix)}},
            }
            found = subs.get((parent, vlan))
            if found:
                body["id"] = found["id"]
                await self.put(f"{base}/subinterfaces/{found['id']}", body, f"{parent}.{vlan}")
                continue
            try:
                await self.fmc.write_json("POST", self.path(f"{base}/subinterfaces"), body)
                log(f"  created {parent}.{vlan} {ifname} {address}/{prefix}")
            except FmcWriteRejectedError as exc:
                log(f"  rejected {parent}.{vlan}: {exc.description[:200]}")
        self.save()
        await self.routes(base)

    def zone(self, name: str) -> dict[str, str]:
        z = self.m["zones"][f"Z_{name}"]
        return {"id": z["id"], "type": "SecurityZone", "name": z["name"]}

    async def put(self, suffix: str, body: dict[str, Any], label: str) -> None:
        try:
            await self.fmc.write_json("PUT", self.path(suffix), body)
            log(f"  set {label}")
        except FmcWriteRejectedError as exc:
            log(f"  rejected {label}: {exc.description[:200]}")

    async def routes(self, base: str) -> None:
        log("static routes")
        builtin = await self.by_name("/object/networks")
        existing = {
            (
                r.get("interfaceName"),
                tuple(sorted(n["name"] for n in r.get("selectedNetworks", []))),
            ): r
            for r in await self.all(f"{base}/routing/ipv4staticroutes", expanded="true")
        }
        for network, ifname, gateway in ROUTES:
            if network == "any-ipv4":
                obj = builtin.get("any-ipv4")
                ref = {"id": obj["id"], "type": obj["type"], "name": "any-ipv4"} if obj else None
            else:
                ref = await self.ensure(
                    "/object/networks",
                    {
                        "name": "RT_" + network.replace("/", "_"),
                        "type": "Network",
                        "value": network,
                        "description": MARK,
                    },
                )
            if ref is None:
                continue
            found = existing.get((ifname, (ref["name"],)))
            if found is not None:
                if ((found.get("gateway") or {}).get("literal") or {}).get("value") != gateway:
                    body = {k: v for k, v in found.items() if k not in SKIP}
                    body["gateway"] = {"literal": {"type": "Host", "value": gateway}}
                    await self.put(
                        f"{base}/routing/ipv4staticroutes/{found['id']}",
                        body,
                        f"route {network} gateway {gateway}",
                    )
                continue
            try:
                await self.fmc.write_json(
                    "POST",
                    self.path(f"{base}/routing/ipv4staticroutes"),
                    {
                        "type": "IPv4StaticRoute",
                        "interfaceName": ifname,
                        "selectedNetworks": [ref],
                        "metricValue": 1,
                        "isTunneled": False,
                        "gateway": {"literal": {"type": "Host", "value": gateway}},
                    },
                )
                log(f"  route {network} -> {ifname} {gateway}")
            except FmcWriteRejectedError as exc:
                log(f"  rejected route {network}: {exc.description[:200]}")

    # ------------------------------------------------------------------ objects

    async def objects(self) -> None:
        log("VLAN tags")
        for name, start, end in (
            ("VLAN_CORE", 100, 100),
            ("VLAN_GOLD", 1120, 1120),
            ("VLAN_USERS", 102, 104),
            ("VLAN_PAW", 105, 105),
            ("VLAN_LEGACY", 170, 179),
        ):
            await self.ensure(
                "/object/vlantags",
                {
                    "name": name,
                    "type": "VlanTag",
                    "description": MARK,
                    "data": {"type": "VlanTagLiteral", "startTag": start, "endTag": end},
                },
            )
        await self.ensure(
            "/object/vlangrouptags",
            {
                "name": "VLANGRP_DC",
                "type": "VlanGroupTag",
                "description": MARK,
                "objects": [
                    self.ref(n) for n in ("VLAN_CORE", "VLAN_GOLD") if n in self.m["objects"]
                ],
            },
        )
        log("URLs")
        for name, url in (
            ("URL_PORTAL", "portal.example.com"),
            ("URL_PAY_API", "pay-api.example.com/v2"),
            ("URL_UPDATES", "updates.vendor.example"),
            ("URL_PARTNER_SFTP", "sftp.partner.example"),
            ("URL_LEGACY_APP", "http://legacy.example.local/app"),
        ):
            await self.ensure(
                "/object/urls", {"name": name, "type": "Url", "url": url, "description": MARK}
            )
        await self.ensure(
            "/object/urlgroups",
            {
                "name": "URLGRP_BUSINESS",
                "type": "UrlGroup",
                "description": MARK,
                "objects": [
                    self.ref(n)
                    for n in ("URL_PORTAL", "URL_PAY_API", "URL_UPDATES")
                    if n in self.m["objects"]
                ],
            },
        )
        log("time ranges")
        await self.ensure(
            "/object/timeranges",
            {
                "name": "TR_BUSINESS_HOURS",
                "type": "TimeRange",
                "description": MARK,
                "effectiveStartDateTime": "2026-01-01T00:00",
                "effectiveEndDateTime": "2030-12-31T23:59",
                "recurrenceList": [
                    {
                        "recurrenceType": "DAILY_INTERVAL",
                        "dailyStartTime": "08:00",
                        "dailyEndTime": "18:00",
                        "days": ["MON", "TUE", "WED", "THU", "FRI"],
                    }
                ],
            },
        )
        await self.ensure(
            "/object/timeranges",
            {
                "name": "TR_MAINT_WINDOW",
                "type": "TimeRange",
                "description": MARK,
                "effectiveStartDateTime": "2026-01-01T00:00",
                "effectiveEndDateTime": "2027-12-31T23:59",
                "recurrenceList": [
                    {
                        "recurrenceType": "RANGE",
                        "rangeStartDay": "SAT",
                        "rangeStartTime": "22:00",
                        "rangeEndDay": "SUN",
                        "rangeEndTime": "04:00",
                    }
                ],
            },
        )
        log("ICMP objects")
        for name, icmp_type, code in (
            ("ICMP_ECHO", "8", None),
            ("ICMP_ECHO_REPLY", "0", None),
            ("ICMP_FRAG_NEEDED", "3", 4),
        ):
            body: dict[str, Any] = {
                "name": name,
                "type": "ICMPV4Object",
                "icmpType": icmp_type,
                "description": MARK,
            }
            if code is not None:
                body["code"] = code
            await self.ensure("/object/icmpv4objects", body)
        await self.ensure(
            "/object/icmpv6objects",
            {"name": "ICMP6_ECHO", "type": "ICMPV6Object", "icmpType": "128", "description": MARK},
        )
        log("security group tags (custom SGT)")
        for name, tag in (
            ("SGT_FINANCE", 10),
            ("SGT_HR", 11),
            ("SGT_PCI", 20),
            ("SGT_ADMINS", 30),
            ("SGT_CONTRACTORS", 40),
            ("SGT_IOT", 50),
        ):
            await self.ensure(
                "/object/securitygrouptags",
                {"name": name, "type": "SecurityGroupTag", "tag": tag, "description": MARK},
            )
        log("interface groups")
        await self.ensure(
            "/object/interfacegroups",
            {
                "name": "IG_USER_SITES",
                "type": "InterfaceGroup",
                "interfaceMode": "ROUTED",
                "description": MARK,
            },
        )

    def ref(self, name: str) -> dict[str, str]:
        o = self.m["objects"][name]
        return {"id": o["id"], "type": o["type"], "name": name}

    # ------------------------------------------------------------------ inspection

    async def inspection(self) -> None:
        log("intrusion policies")
        builtin = await self.by_name("/policy/intrusionpolicies")
        for name, (base_name, mode) in IPS_POLICIES.items():
            base = builtin.get(base_name)
            if base is None:
                log(f"  no base policy {base_name}")
                continue
            await self.ensure(
                "/policy/intrusionpolicies",
                {
                    "name": name,
                    "type": "IntrusionPolicy",
                    "description": MARK,
                    "inspectionMode": mode,
                    "basePolicy": {"id": base["id"], "type": "IntrusionPolicy", "name": base_name},
                },
                "ips",
            )
        log("file policy")
        await self.ensure(
            "/policy/filepolicies",
            {"name": "DF-FILE-MALWARE", "type": "FilePolicy", "description": MARK},
            "policies",
        )

    # ------------------------------------------------------------------ decryption

    async def decryption(self) -> None:
        log("internal CA and certificate (generated now, never stored)")
        ca_cert, ca_key = _self_signed("DF Lab Resign CA", ca=True)
        await self.ensure(
            "/object/internalcas",
            {
                "name": "DF-LAB-RESIGN-CA",
                "type": "InternalCA",
                "cert": ca_cert,
                "privateKey": ca_key,
            },
            "policies",
        )
        log("decryption policy")
        pol = await self.ensure(
            "/policy/decryptionpolicies",
            {"name": "DF-LAB-SSL", "type": "DecryptionPolicy", "description": MARK},
            "policies",
        )
        if pol is not None:
            await self.decryption_rules(pol["id"])
        log("identity policy")
        ident = await self.ensure(
            "/policy/identitypolicies",
            {"name": "DF-LAB-IDENTITY", "type": "IdentityPolicy", "description": MARK},
            "policies",
        )
        if ident is not None:
            await self.identity_rules(ident["id"])

    async def identity_rules(self, pid: str) -> None:
        """FMC 10.1.1 identity rules: zones are plain arrays, the "action" is
        ``authenticationType`` (PASSIVE / ACTIVE / NO). Passive / active need an AD realm,
        which a lab without AD does not have: those are attempted and logged if refused."""
        suffix = f"/policy/identitypolicies/{pid}/identityrules"
        have = {r.get("name") for r in await self.all(suffix)}
        realms = await self.by_name("/object/realms")
        realm = next(
            (
                r
                for n, r in realms.items()
                if n not in ("Discovered Identities", "Special Identities")
            ),
            None,
        )
        rules: list[dict[str, Any]] = [
            {
                "name": "NO-AUTH-SERVERS",
                "authenticationType": "NO",
                "sourceZones": [self.zone("GOLD"), self.zone("SILVER")],
            },
            {
                "name": "NO-AUTH-PARTNERS",
                "authenticationType": "NO",
                "sourceZones": [self.zone("PARTNERS")],
                "destinationNetworks": {"literals": [{"type": "Network", "value": "10.30.0.0/16"}]},
            },
        ]
        if realm is not None:
            rules.append(
                {
                    "name": "PASSIVE-USERS",
                    "authenticationType": "PASSIVE",
                    "sourceZones": [self.zone("USERS")],
                    "realm": {"id": realm["id"], "type": realm["type"], "name": realm["name"]},
                }
            )
        for rule in rules:
            if rule["name"] in have:
                continue
            body = {"type": "IdentityRule", "enabled": True, **rule}
            try:
                await self.fmc.write_json("POST", self.path(suffix), body)
                log(f"  identity rule {rule['name']} ({rule['authenticationType']})")
            except FmcError as exc:  # 10.1.1 answers 500 to some identity rules
                log(f"  identity rule {rule['name']} not created: {str(exc)[:200]}")

    async def decryption_rules(self, pid: str) -> None:
        suffix = f"/policy/decryptionpolicies/{pid}/decryptionpolicyrules"
        have = {r["name"] for r in await self.all(suffix)}
        nets = await self.by_name("/object/networks")
        hosts = await self.by_name("/object/hosts")
        groups = await self.by_name("/object/networkgroups")

        def net(name: str) -> dict[str, str] | None:
            for pool in (groups, nets, hosts):
                if name in pool:
                    return {"id": pool[name]["id"], "type": pool[name]["type"], "name": name}
            return None

        def nets_of(*names: str) -> dict[str, Any]:
            refs = [r for r in (net(n) for n in names) if r]
            return (
                {"objects": refs}
                if refs
                else {"literals": [{"type": "Network", "value": "10.0.0.0/24"}]}
            )

        ca = self.m["policies"].get("DF-LAB-RESIGN-CA")
        rules: list[dict[str, Any]] = [
            {
                "name": "DND-CORE-IDENTITY",
                "ruleAction": "DO_NOT_DECRYPT",
                "destinationNetworks": nets_of("GRP_SVC_DC", "GRP_SVC_PKI", "GRP_SVC_RADIUS"),
            },
            {
                "name": "DND-LDAPS-GC",
                "ruleAction": "DO_NOT_DECRYPT",
                "destinationPorts": {
                    "literals": [
                        {"type": "PortLiteral", "protocol": "6", "port": "636"},
                        {"type": "PortLiteral", "protocol": "6", "port": "3269"},
                    ]
                },
            },
            {
                "name": "DND-BANKING-HEALTH",
                "ruleAction": "DO_NOT_DECRYPT",
                "sourceZones": {"objects": [self.zone("USERS")]},
                "destinationZones": {"objects": [self.zone("OUTSIDE")]},
                "description": "regulatory bypass (URL categories set in the UI)",
            },
            {
                "name": "BLOCK-OLD-TLS-PARTNERS",
                "ruleAction": "BLOCK",
                "sourceZones": {"objects": [self.zone("PARTNERS")]},
            },
            {
                "name": "MONITOR-LEGACY",
                "ruleAction": "MONITOR",
                "sourceZones": {"objects": [self.zone("BRONZE")]},
                "enabled": False,
            },
        ]
        if ca:
            rules.insert(
                4,
                {
                    "name": "RESIGN-USERS-OUT",
                    "ruleAction": "DECRYPT_RESIGN",
                    "sourceZones": {"objects": [self.zone("USERS")]},
                    "destinationZones": {"objects": [self.zone("OUTSIDE")]},
                    "decryptionCerts": {
                        "objects": [{"id": ca["id"], "type": "InternalCA", "name": ca["name"]}]
                    },
                    "logging": {"logEnd": True, "sendEvents": True},
                },
            )
            rules.insert(
                5,
                {
                    "name": "RESIGN-HTTPS-GOLD",
                    "ruleAction": "DECRYPT_RESIGN",
                    "destinationNetworks": nets_of("NET_FIN-DB", "NET_PAY-DB"),
                    "destinationPorts": {
                        "literals": [{"type": "PortLiteral", "protocol": "6", "port": "443"}]
                    },
                    "decryptionCerts": {
                        "objects": [{"id": ca["id"], "type": "InternalCA", "name": ca["name"]}]
                    },
                    "logging": {"logEnd": True, "sendEvents": True},
                },
            )
        for rule in rules:
            if rule["name"] in have:
                continue
            body = {"type": "DecryptionPolicyRule", "enabled": True, **rule}
            try:
                await self.fmc.write_json("POST", self.path(suffix), body)
                log(f"  rule {rule['name']} ({rule['ruleAction']})")
            except FmcWriteRejectedError as exc:
                log(f"  rejected rule {rule['name']}: {exc.description[:240]}")

    # ------------------------------------------------------------------ link

    async def link(self) -> None:
        """Every access policy uses the decryption and identity policies (as in production)."""
        log("link decryption / identity policies to the access policies")
        ssl = self.m["policies"].get("DF-LAB-SSL")
        ident = self.m["policies"].get("DF-LAB-IDENTITY")
        for item in await self.all("/policy/accesspolicies"):
            path = f"/policy/accesspolicies/{item['id']}"
            cur = await self.fmc.get_json(self.path(path))
            body = {k: v for k, v in cur.items() if k not in (*SKIP, "rules")}
            if ssl:
                ref = {"id": ssl["id"], "type": "DecryptionPolicy", "name": ssl["name"]}
                body["decryptionPolicySetting"] = {**ref, "decryptionPolicy": ref}
            if ident:
                body["identityPolicySetting"] = {
                    "id": ident["id"],
                    "type": "IdentityPolicy",
                    "name": ident["name"],
                }
            await self.put(path, body, f"access policy {item['name']}")


def _self_signed(cn: str, *, ca: bool) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), pem_key.decode()


async def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "step", choices=("network", "objects", "inspection", "decryption", "link", "all")
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=Path("/work"))
    parser.add_argument("--no-deploy", action="store_true")
    parser.add_argument("--yes-write-to-lab", action="store_true")
    args = parser.parse_args()
    if not args.yes_write_to_lab:
        print("refusing to write to the FMC without --yes-write-to-lab", file=sys.stderr)
        return 2
    password = os.environ.pop("DF_LAB_PASSWORD", "") or sys.stdin.readline().rstrip("\n")
    if not password:
        print("no password (DF_LAB_PASSWORD or stdin)", file=sys.stderr)
        return 2
    secret = bytearray(password.encode())
    del password
    args.work.mkdir(parents=True, exist_ok=True)
    try:
        async with FmcSession(
            host=args.host,
            port=args.port,
            username=args.user,
            password_provider=lambda: bytearray(secret),
            ssl_context=build_ssl_context(args.ca),
            timeout=300,
            throttle=ThrottlePolicy(requests_per_minute=100, connect_retries=5),
        ) as fmc:
            log(f"FMC {await server_version(fmc)}")
            ops = Ops(fmc, args.work)
            steps = ("network", "objects", "inspection", "decryption", "link")
            for step in steps if args.step == "all" else (args.step,):
                await getattr(ops, step)()
            if not args.no_deploy:
                await ops.deploy_pending(args.step)
            log(f"{args.step} done")
    except FmcError as exc:
        print(f"FMC error: {exc.code}: {getattr(exc, 'description', '') or exc}", file=sys.stderr)
        return 1
    finally:
        secret[:] = b"\0" * len(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
