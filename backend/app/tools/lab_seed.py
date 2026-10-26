"""Build a doctrine lab scenario in a LAB FMC: objects, groups, ports and access rules.

Only for lab systems — it WRITES to the FMC configuration (it never deploys)::

    docker run --rm -e DF_LAB_PASSWORD --add-host firepower:<ip> -v <fmc-cert.pem>:/ca.pem:ro \\
        doctor-firewall/api:dev python -m app.tools.lab_seed --host firepower --user admin \\
        --ca /ca.pem --policy FTDv-Cluster --yes-write-to-lab [--cleanup]

* The password comes from ``DF_LAB_PASSWORD`` (or stdin); it is never printed or stored.
* TLS is fully verified against ``--ca`` (for a self-signed lab FMC: its own certificate).
* Idempotent: anything that already exists by name is left alone (not modified).
* Everything created carries ``MARK`` in its description (objects) or the ``LAB_`` name
  prefix (rules); ``--cleanup`` deletes exactly those, rules first.

The scenario follows the doctrine (users / GOLD / SILVER / BRONZE / CORE) and contains the
problems the analysis must find: a BRONZE -> GOLD tier skip, any -> any, shadowed rules, rules to
merge and to split, a nested group chain with redundant references and members, duplicate
values, inline literals, a Trust rule to GOLD, a GOLD rule without IPS and an unused group.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError, FmcWriteRejectedError

MARK = "df-lab-seed"
RULE_PREFIX = "LAB_"

HOSTS = {
    "H_SQL_FIN_1": "10.20.5.11",
    "H_SQL_FIN_2": "10.20.5.12",
    "H_DBA_PAW": "10.100.20.50",
    "H_DNS_1": "10.0.0.53",
    "H_DNS_2": "10.0.0.54",
    "dns-primary": "10.0.0.53",  # same value, another name (duplicate)
    "H_DC_1": "10.0.0.10",
    "H_DC_2": "10.0.0.11",
    "H_NTP": "10.0.0.123",
}
NETWORKS = {
    "NET_USERS_FIN": "10.100.10.0/24",
    "NET_USERS_IT": "10.100.20.0/24",
    "NET_USERS_GENERAL": "10.100.30.0/24",
    "NET_GOLD_DB": "10.20.5.0/24",
    "NET_10.20.5.0": "10.20.5.0/24",  # duplicate of NET_GOLD_DB, named by address
    "NET_APP_FIN": "10.30.10.0/24",
    "NET_APP_HR": "10.30.20.0/24",
    "NET_DEV": "10.40.0.0/16",
    "NET_QUARANTINE": "10.66.0.0/16",
}
PORTS = {
    "TCP_1433": ("TCP", "1433"),
    "TCP_443": ("TCP", "443"),
    "TCP_22": ("TCP", "22"),
    "TCP_3389": ("TCP", "3389"),
    "UDP_53": ("UDP", "53"),
    "TCP_53": ("TCP", "53"),
    "TCP_389": ("TCP", "389"),
    "TCP_636": ("TCP", "636"),
    "TCP_88": ("TCP", "88"),
}
PORT_GROUPS = {"PG_DNS": ["UDP_53", "TCP_53"], "PG_AD": ["TCP_389", "TCP_636", "TCP_88"]}
# Order matters: members before the groups containing them.
GROUPS: list[tuple[str, list[str]]] = [
    ("GRP_SRV_GOLD", ["H_SQL_FIN_1", "H_SQL_FIN_2"]),
    ("GRP_SVC_DNS", ["H_DNS_1", "dns-primary", "H_DNS_2"]),
    ("GRP_SVC_AD", ["H_DC_1", "H_DC_2"]),
    ("GRP_CORE_ALL", ["GRP_SVC_DNS", "GRP_SVC_AD", "H_NTP"]),
    ("GRP_USERS_ALL", ["NET_USERS_FIN", "NET_USERS_IT", "NET_USERS_GENERAL"]),
    ("GRP_MIXED_TIERS", ["NET_GOLD_DB", "NET_APP_FIN"]),
    ("GRP_UNUSED", ["NET_APP_HR"]),
    # A nested chain; level 3 holds the host again directly (redundant member).
    ("LAB_CHAIN_1", ["H_SQL_FIN_1"]),
    ("LAB_CHAIN_2", ["LAB_CHAIN_1"]),
    ("LAB_CHAIN_3", ["LAB_CHAIN_2", "H_SQL_FIN_1"]),
    ("LAB_CHAIN_4", ["LAB_CHAIN_3"]),
    ("LAB_CHAIN_5", ["LAB_CHAIN_4"]),
    ("LAB_CHAIN_6", ["LAB_CHAIN_5"]),
]
# Rules in evaluation order. Keys: action (default ALLOW), src / dst object names,
# src_literals / dst_literals, ports, ips (intrusion policy name), enabled.
RULES: list[dict[str, Any]] = [
    {"name": "LAB_BLOCK_QUARANTINE", "action": "BLOCK", "src": ["NET_QUARANTINE"]},
    {"name": "LAB_CORE_DNS", "src": ["GRP_USERS_ALL"], "dst": ["GRP_SVC_DNS"], "ports": ["PG_DNS"]},
    {"name": "LAB_CORE_AD", "src": ["GRP_USERS_ALL"], "dst": ["GRP_SVC_AD"], "ports": ["PG_AD"]},
    {
        "name": "LAB_FIN_TO_GOLD_SQL",
        "src": ["NET_USERS_FIN"],
        "dst": ["GRP_SRV_GOLD"],
        "ports": ["TCP_1433"],
    },
    {
        "name": "LAB_DBA_TO_GOLD",
        "src": ["H_DBA_PAW"],
        "dst": ["GRP_SRV_GOLD"],
        "ports": ["TCP_1433", "TCP_3389"],
        "ips": "Balanced Security and Connectivity",
    },
    {
        "name": "LAB_DEV_TO_GOLD_DB",
        "src": ["NET_DEV"],
        "dst": ["NET_GOLD_DB"],
        "ports": ["TCP_1433"],
    },
    {
        "name": "LAB_USERS_TO_APPS",
        "src": ["GRP_USERS_ALL"],
        "dst": ["NET_APP_FIN", "NET_APP_HR"],
        "ports": ["TCP_443"],
    },
    {
        "name": "LAB_FIN_TO_APP_FIN",
        "src": ["NET_USERS_FIN"],
        "dst": ["NET_APP_FIN"],
        "ports": ["TCP_443"],
    },
    {
        "name": "LAB_IT_TO_MIXED",
        "src": ["NET_USERS_IT"],
        "dst": ["GRP_MIXED_TIERS"],
        "ports": ["TCP_443", "TCP_1433"],
    },
    {"name": "LAB_WEB_FIN", "src": ["NET_USERS_FIN"], "dst": ["NET_APP_HR"], "ports": ["TCP_22"]},
    {"name": "LAB_WEB_IT", "src": ["NET_USERS_IT"], "dst": ["NET_APP_HR"], "ports": ["TCP_22"]},
    {
        "name": "LAB_CHAIN_RULE",
        "src": ["NET_USERS_IT"],
        "dst": ["LAB_CHAIN_6", "LAB_CHAIN_3", "H_SQL_FIN_1"],
        "ports": ["TCP_1433"],
    },
    {
        "name": "LAB_LITERALS",
        "src_literals": ["10.50.0.0/16"],
        "dst_literals": ["10.20.5.11"],
        "ports": ["TCP_1433"],
    },
    {
        "name": "LAB_TRUST_DBA_SSH",
        "action": "TRUST",
        "src": ["H_DBA_PAW"],
        "dst": ["NET_GOLD_DB"],
        "ports": ["TCP_22"],
    },
    {
        "name": "LAB_OLD_DISABLED",
        "src": ["NET_USERS_GENERAL"],
        "dst": ["NET_DEV"],
        "enabled": False,
    },
    {"name": "LAB_TEMP_ANY_ANY"},
]
NETWORK_TYPES = {"hosts": "Host", "networks": "Network", "networkgroups": "NetworkGroup"}
PORT_TYPES = {"protocolportobjects": "ProtocolPortObject", "portobjectgroups": "PortObjectGroup"}


class Lab:
    def __init__(self, fmc: FmcSession, *, dry_run: bool) -> None:
        self.fmc = fmc
        self.dry_run = dry_run
        self.index: dict[str, dict[str, Any]] = {}  # name -> {id, type, name}
        self.created = 0
        self.skipped = 0

    def path(self, suffix: str) -> str:
        return f"/api/fmc_config/v1/domain/{self.fmc.domain_uuid}{suffix}"

    async def all(self, suffix: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        async for _offset, page in self.fmc.iter_pages(self.path(suffix)):
            items.extend(page)
        return items

    async def load(self) -> None:
        for resource in (*NETWORK_TYPES, *PORT_TYPES):
            for item in await self.all(f"/object/{resource}"):
                self.index.setdefault(
                    item["name"], {"id": item["id"], "type": item["type"], "name": item["name"]}
                )

    async def create(self, resource: str, body: dict[str, Any]) -> None:
        name = body["name"]
        if name in self.index:
            self.skipped += 1
            return
        print(f"create {resource[:-1]:<20} {name}")
        if self.dry_run:
            self.index[name] = {"id": f"dry-{name}", "type": body["type"], "name": name}
            return
        made = await self.fmc.write_json("POST", self.path(f"/object/{resource}"), body)
        self.index[name] = {"id": made["id"], "type": made["type"], "name": made["name"]}
        self.created += 1

    def ref(self, name: str) -> dict[str, str]:
        found = self.index[name]
        return {"id": found["id"], "type": found["type"], "name": found["name"]}

    async def objects(self) -> None:
        for name, value in HOSTS.items():
            await self.create(
                "hosts", {"name": name, "value": value, "type": "Host", "description": MARK}
            )
        for name, value in NETWORKS.items():
            await self.create(
                "networks", {"name": name, "value": value, "type": "Network", "description": MARK}
            )
        for name, (proto, port) in PORTS.items():
            await self.create(
                "protocolportobjects",
                {
                    "name": name,
                    "protocol": proto,
                    "port": port,
                    "type": "ProtocolPortObject",
                    "description": MARK,
                },
            )
        for name, members in PORT_GROUPS.items():
            await self.create(
                "portobjectgroups",
                {
                    "name": name,
                    "objects": [self.ref(m) for m in members],
                    "type": "PortObjectGroup",
                    "description": MARK,
                },
            )
        for name, members in GROUPS:
            await self.create(
                "networkgroups",
                {
                    "name": name,
                    "objects": [self.ref(m) for m in members],
                    "type": "NetworkGroup",
                    "description": MARK,
                },
            )

    async def policy_id(self, name: str) -> str:
        for item in await self.all("/policy/accesspolicies"):
            if item["name"] == name:
                return str(item["id"])
        raise SystemExit(f"access policy {name!r} not found")

    async def rules(self, policy: str) -> None:
        pid = await self.policy_id(policy)
        existing = {r["name"] for r in await self.all(f"/policy/accesspolicies/{pid}/accessrules")}
        ips = {p["name"]: p for p in await self.all("/policy/intrusionpolicies")}
        variable_sets = {v["name"]: v for v in await self.all("/object/variablesets")}
        for spec in RULES:
            if spec["name"] in existing:
                self.skipped += 1
                continue
            body: dict[str, Any] = {
                "name": spec["name"],
                "type": "AccessRule",
                "action": spec.get("action", "ALLOW"),
                "enabled": spec.get("enabled", True),
                "sendEventsToFMC": True,
            }
            # The FMC logs blocked connections at their start only (logEnd is refused for BLOCK).
            blocking = body["action"] in ("BLOCK", "BLOCK_RESET")
            body["logBegin"], body["logEnd"] = blocking, not blocking
            nets = (
                ("src", "src_literals", "sourceNetworks"),
                ("dst", "dst_literals", "destinationNetworks"),
            )
            for names_key, literal_key, field in nets:
                part: dict[str, Any] = {}
                if spec.get(names_key):
                    part["objects"] = [self.ref(n) for n in spec[names_key]]
                if spec.get(literal_key):
                    part["literals"] = [
                        {"type": "Network" if "/" in v else "Host", "value": v}
                        for v in spec[literal_key]
                    ]
                if part:
                    body[field] = part
            if spec.get("ports"):
                body["destinationPorts"] = {"objects": [self.ref(p) for p in spec["ports"]]}
            if spec.get("ips") and spec["ips"] in ips and "Default-Set" in variable_sets:
                policy_ref = ips[spec["ips"]]
                body["ipsPolicy"] = {
                    "id": policy_ref["id"],
                    "name": policy_ref["name"],
                    "type": "IntrusionPolicy",
                }
                vs = variable_sets["Default-Set"]
                body["variableSet"] = {"id": vs["id"], "name": vs["name"], "type": "VariableSet"}
            print(f"create rule                 {spec['name']}")
            if not self.dry_run:
                await self.fmc.write_json(
                    "POST",
                    self.path(f"/policy/accesspolicies/{pid}/accessrules"),
                    body,
                    {"section": "mandatory"},
                )
                self.created += 1

    async def cleanup(self, policy: str) -> None:
        pid = await self.policy_id(policy)
        for rule in await self.all(f"/policy/accesspolicies/{pid}/accessrules"):
            if str(rule["name"]).startswith(RULE_PREFIX):
                print(f"delete rule   {rule['name']}")
                if not self.dry_run:
                    await self.fmc.write_json(
                        "DELETE",
                        self.path(f"/policy/accesspolicies/{pid}/accessrules/{rule['id']}"),
                    )
        # Containers before their members: groups (reverse order), port groups, then leaves.
        order = [
            *(("networkgroups", n) for n, _ in reversed(GROUPS)),
            *(("portobjectgroups", n) for n in PORT_GROUPS),
            *(("protocolportobjects", n) for n in PORTS),
            *(("networks", n) for n in NETWORKS),
            *(("hosts", n) for n in HOSTS),
        ]
        marked = {}
        for resource in {r for r, _ in order}:
            for item in await self.all(f"/object/{resource}"):
                if (item.get("description") or "").strip() == MARK:
                    marked[(resource, item["name"])] = item["id"]
        for resource, name in order:
            oid = marked.get((resource, name))
            if oid is None:
                continue
            print(f"delete {resource[:-1]:<20} {name}")
            if not self.dry_run:
                try:
                    await self.fmc.write_json("DELETE", self.path(f"/object/{resource}/{oid}"))
                except FmcWriteRejectedError as exc:
                    print(f"  kept ({exc.description or exc.status})")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--ca", type=Path, required=True, help="CA / pinned certificate of the FMC")
    parser.add_argument("--policy", required=True, help="access policy to add the lab rules to")
    parser.add_argument("--cleanup", action="store_true", help="delete what this tool created")
    parser.add_argument("--dry-run", action="store_true", help="show what would change")
    parser.add_argument(
        "--yes-write-to-lab", action="store_true", help="confirm: this writes to the FMC"
    )
    args = parser.parse_args()
    if not (args.yes_write_to_lab or args.dry_run):
        print("refusing to write without --yes-write-to-lab (or use --dry-run)", file=sys.stderr)
        return 2
    password = os.environ.pop("DF_LAB_PASSWORD", "") or sys.stdin.readline().rstrip("\n")
    if not password:
        print("no password (DF_LAB_PASSWORD or stdin)", file=sys.stderr)
        return 2
    secret = bytearray(password.encode())
    del password
    try:
        async with FmcSession(
            host=args.host,
            port=args.port,
            username=args.user,
            password_provider=lambda: bytearray(secret),
            ssl_context=build_ssl_context(args.ca),
            timeout=60,
            throttle=ThrottlePolicy(requests_per_minute=100),
        ) as fmc:
            lab = Lab(fmc, dry_run=args.dry_run)
            if args.cleanup:
                await lab.cleanup(args.policy)
            else:
                await lab.load()
                await lab.objects()
                await lab.rules(args.policy)
                print(f"created {lab.created}, already present {lab.skipped}")
    except FmcError as exc:
        print(f"FMC error: {exc.code}: {getattr(exc, 'description', '') or exc}", file=sys.stderr)
        return 1
    finally:
        secret[:] = b"\0" * len(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
