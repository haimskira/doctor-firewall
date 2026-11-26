"""Pre-production dry run on a LAB FMC: wipe it, then load four messy access policies.

Only for lab systems — it DELETES policies and objects, WRITES and DEPLOYS::

    docker run --rm -e DF_LAB_PASSWORD --add-host firepower:<ip> \\
        -v <fmc-cert.pem>:/ca.pem:ro -v <work dir>:/work doctor-firewall/api:dev \\
        python -m app.tools.lab_dryrun --host firepower --user admin --ca /ca.pem \\
        wipe|load --yes-wipe-lab

* ``wipe``: creates the scenario's access policies (default action BLOCK), assigns the first one
  to every device / HA pair an access policy was assigned to, deletes every other access policy
  and every prefilter policy but the system default, then every user object the FMC lets go
  (objects still used by NAT, routing or platform settings stay and are listed), and deploys.
* ``load``: the object pool (bulk API), the dynamic objects and their mappings, one prefilter
  policy (BLOCK bogons, FASTPATH DNS) linked to every scenario policy, and each policy's rules in
  chunks of ``--deploy-limit`` with categories; pending changes are deployed after each chunk.
* Progress is kept in ``/work/manifest.json``: re-running resumes. ``/work/assets.csv`` is the
  scenario's asset table (with declared services). The password comes from ``DF_LAB_PASSWORD``
  (or stdin) and is never printed or stored.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError, FmcWriteRejectedError
from app.fmc.probe import server_version
from app.tools.lab_scale import MARK, Loader, log
from app.tools.lab_scenario import RuleSpec, Scenario, build_policies

PREFILTER = "DF-LAB-PREFILTER"
OBJECT_RESOURCES = (  # deletion order: containers before their members
    "networkgroups",
    "portobjectgroups",
    "urlgroups",
    "dynamicobjects",
    "hosts",
    "networks",
    "ranges",
    "fqdns",
    "protocolportobjects",
    "icmpv4objects",
    "icmpv6objects",
    "urls",
)
POLICY_TYPES = {"accesspolicies": "AccessPolicy", "prefilterpolicies": "PrefilterPolicy"}
# Address prefix -> zone, for objects the scenario does not tier (DMZ, partners, literals).
PREFIX_ZONES = (
    ("10.0.0.", "CORE"),
    ("10.20.", "GOLD"),
    ("10.30.", "SILVER"),
    ("10.4", "BRONZE"),
    ("10.5", "BRONZE"),
    ("10.6", "BRONZE"),
    ("10.10", "USERS"),
    ("172.16.", "DMZ"),
    ("198.51.", "PARTNERS"),
)
SGT_BY_DEPT = {"FIN": "SGT_FINANCE", "HR": "SGT_HR", "IT": "SGT_ADMINS", "SEC": "SGT_ADMINS"}


class DryRun(Loader):
    def __init__(self, fmc: FmcSession, work: Path, scenario: Scenario) -> None:
        super().__init__(fmc, work, scenario, next(iter(scenario.policies)))
        self.m.setdefault("policies", {})
        self.m.setdefault("dynamic", {})
        # The operational layer (lab_ops): zones, the IPS, file policy, SGT, VLAN, URL, time.
        ops_path = work / "ops.json"
        self.ops: dict[str, Any] = (
            json.loads(ops_path.read_text(encoding="utf-8")) if ops_path.is_file() else {}
        )

    # ---- helpers

    async def policy_id(self, name: str, resource: str = "accesspolicies") -> str | None:
        for item in await self.all(f"/policy/{resource}"):
            if item["name"] == name:
                return str(item["id"])
        return None

    async def ensure_policy(self, name: str) -> str:
        found = await self.policy_id(name)
        if found is not None:
            return found
        made = await self.fmc.write_json(
            "POST",
            self.path("/policy/accesspolicies"),
            {
                "name": name,
                "type": "AccessPolicy",
                "description": MARK,
                "defaultAction": {"action": "BLOCK", "logBegin": True},
            },
        )
        log(f"access policy {name} created")
        return str(made["id"])

    # ---- wipe

    async def wipe(self, do_deploy: bool) -> None:
        names = list(self.sc.policies)
        ids = {name: await self.ensure_policy(name) for name in names}
        first = ids[names[0]]
        # Every device / HA pair an access policy governs moves to the first scenario policy.
        targets: dict[str, dict[str, str]] = {}
        for item in await self.all("/assignment/policyassignments"):
            policy = item.get("policy") or {}
            if policy.get("type") != "AccessPolicy" or policy.get("id") == first:
                continue
            for t in item.get("targets") or []:
                targets[str(t["id"])] = {"id": str(t["id"]), "type": str(t["type"])}
        if targets:
            await self.fmc.write_json(
                "POST",
                self.path("/assignment/policyassignments"),
                {
                    "type": "PolicyAssignment",
                    "policy": {"id": first, "type": "AccessPolicy"},
                    "targets": list(targets.values()),
                },
            )
            log(f"{len(targets)} device target(s) assigned to {names[0]}")
        # Old access policies, then prefilter policies (not the system default).
        for resource, keep in (("accesspolicies", set(ids.values())), ("prefilterpolicies", set())):
            for item in await self.all(f"/policy/{resource}"):
                if item["id"] in keep or item["name"] == "Default Prefilter Policy":
                    continue
                try:
                    await self.fmc.write_json(
                        "DELETE", self.path(f"/policy/{resource}/{item['id']}")
                    )
                    log(f"deleted {resource[:-8]} policy {item['name']}")
                except FmcWriteRejectedError as exc:
                    log(f"  kept {resource[:-8]} policy {item['name']}: {exc.description[:120]}")
        # User objects: ask the FMC which are unused (GET filter unusedOnly — DELETE does not
        # take it), delete those in bulk by id; repeat while something goes (a deleted group
        # frees its members).
        for round_ in range(1, 15):
            removed = 0
            for resource in OBJECT_RESOURCES:
                try:
                    unused = await self.all(f"/object/{resource}", {"filter": "unusedOnly:true"})
                except FmcError:
                    continue
                unused_ids = [
                    str(i["id"])
                    for i in unused
                    if not ((i.get("metadata") or {}).get("readOnly") or {}).get("state")
                ]
                for start in range(0, len(unused_ids), 50):
                    chunk = unused_ids[start : start + 50]
                    try:
                        await self.fmc.write_json(
                            "DELETE",
                            self.path(f"/object/{resource}"),
                            None,
                            {"bulk": "true", "filter": "ids:" + ",".join(chunk)},
                        )
                        removed += len(chunk)
                    except FmcWriteRejectedError:
                        for oid in chunk:  # one refused: the others still go
                            try:
                                await self.fmc.write_json(
                                    "DELETE", self.path(f"/object/{resource}/{oid}")
                                )
                                removed += 1
                            except FmcWriteRejectedError:
                                continue
                    except FmcError as exc:
                        # The lab link drops now and then: pause; the next round retries.
                        log(f"  {resource}: {exc.code}, pausing")
                        await asyncio.sleep(20)
            log(f"wipe round {round_}: {removed} unused objects deleted")
            if removed == 0:
                break
        # The unusedOnly listing misses some; a last sweep tries each remaining object (groups
        # first, twice: a deleted group frees its members). What the FMC refuses is in use.
        for _ in range(2):
            for resource in OBJECT_RESOURCES:
                for item in await self.all(f"/object/{resource}"):
                    if ((item.get("metadata") or {}).get("readOnly") or {}).get("state"):
                        continue
                    try:
                        await self.fmc.write_json(
                            "DELETE", self.path(f"/object/{resource}/{item['id']}")
                        )
                    except FmcWriteRejectedError:
                        continue
        left = {
            str(item["name"])
            for resource in OBJECT_RESOURCES
            for item in await self.all(f"/object/{resource}")
            if not ((item.get("metadata") or {}).get("readOnly") or {}).get("state")
        }
        log(f"{len(left)} user objects still in use (NAT, routing, platform): kept")
        for name in sorted(left)[:40]:
            log(f"  kept {name}")
        self.m.update(objects={}, rules={}, policies={}, dynamic={}, categories=[])
        self.save()
        if do_deploy:
            await self.deploy_now("wipe")

    # ---- load

    async def dynamic_objects(self) -> None:
        for name, mappings in self.sc.dynamic.items():
            if name in self.m["dynamic"]:
                continue
            made = await self.fmc.write_json(
                "POST",
                self.path("/object/dynamicobjects"),
                {"name": name, "type": "DynamicObject", "objectType": "IP", "description": MARK},
            )
            await self.fmc.write_json(
                "POST",
                self.path("/object/dynamicobjectmappings"),
                {"add": [{"mappings": mappings, "dynamicObject": {"id": made["id"]}}]},
            )
            self.m["dynamic"][name] = {"id": made["id"], "type": "DynamicObject"}
            self.save()
        log(f"dynamic objects: {len(self.m['dynamic'])}")

    async def prefilter(self) -> str:
        pid = await self.policy_id(PREFILTER, "prefilterpolicies")
        if pid is None:
            made = await self.fmc.write_json(
                "POST",
                self.path("/policy/prefilterpolicies"),
                {
                    "name": PREFILTER,
                    "type": "PrefilterPolicy",
                    "description": MARK,
                    "defaultAction": {"action": "ANALYZE_TUNNELS"},
                },
            )
            pid = str(made["id"])
            base = self.path(f"/policy/prefilterpolicies/{pid}/prefilterrules")
            await self.fmc.write_json(
                "POST",
                base,
                {
                    "name": "BLOCK_BOGONS",
                    "type": "PrefilterRule",
                    "ruleType": "PREFILTER",
                    "action": "BLOCK",
                    "enabled": True,
                    "sourceNetworks": {
                        "literals": [
                            {"type": "Network", "value": "0.0.0.0/8"},
                            {"type": "Network", "value": "240.0.0.0/4"},
                        ]
                    },
                },
            )
            await self.fmc.write_json(
                "POST",
                base,
                {
                    "name": "FASTPATH_CORE_DNS",
                    "type": "PrefilterRule",
                    "ruleType": "PREFILTER",
                    "action": "FASTPATH",
                    "enabled": True,
                    "destinationNetworks": {"objects": [self.ref("GRP_SVC_DNS")]},
                    "destinationPorts": {"objects": [self.ref("SVC_DNS-UDP")]},
                },
            )
            log(f"prefilter policy {PREFILTER} created")
        return pid

    async def link_prefilter(self, policy_id: str, prefilter_id: str) -> None:
        path = self.path(f"/policy/accesspolicies/{policy_id}")
        current = await self.fmc.get_json(path)
        if (current.get("prefilterPolicySetting") or {}).get("id") == prefilter_id:
            return
        # Only what the FMC needs (the full GET answer carries read-only parts it refuses).
        body = {
            "id": current["id"],
            "name": current["name"],
            "type": "AccessPolicy",
            "defaultAction": {
                k: v for k, v in (current.get("defaultAction") or {}).items() if k != "links"
            },
            "prefilterPolicySetting": {"id": prefilter_id, "type": "PrefilterPolicy"},
        }
        try:
            await self.fmc.write_json("PUT", path, body)
        except FmcWriteRejectedError as exc:  # the rules still load; the link is optional
            log(f"  prefilter not linked to {current['name']}: {exc.description[:160]}")

    def rule_body(
        self, r: RuleSpec, ips: dict[str, Any], variables: dict[str, Any] | None
    ) -> dict[str, Any]:
        body = super().rule_body(r, ips, variables)
        self.enrich(r, body, variables)
        if r.dst_dynamic:
            body["destinationDynamicObjects"] = {
                "objects": [
                    {"id": self.m["dynamic"][n]["id"], "type": "DynamicObject", "name": n}
                    for n in r.dst_dynamic
                    if n in self.m["dynamic"]
                ]
            }
        return body

    # ---- operational conditions (only when lab_ops ran first)

    def zone_of(self, names: list[str], literals: list[str]) -> str | None:
        """The one zone all of a side's addresses sit behind, if they agree."""
        zones: set[str | None] = set()
        for name in names:
            obj = self.sc.objects.get(name)
            if obj is None:
                zones.add(None)
                continue
            if obj.tier:
                zones.add(obj.tier)
            elif obj.members:
                zones.add(self.zone_of(obj.members, []))
            else:
                zones.add(self._prefix_zone(obj.value or ""))
        zones.update(self._prefix_zone(v) for v in literals)
        return zones.pop() if len(zones) == 1 else None

    @staticmethod
    def _prefix_zone(value: str) -> str | None:
        return next((z for prefix, z in PREFIX_ZONES if value.startswith(prefix)), None)

    def _ref(self, bucket: str, name: str) -> dict[str, str] | None:
        found = (self.ops.get(bucket) or {}).get(name)
        return {"id": found["id"], "type": found["type"], "name": name} if found else None

    def enrich(
        self, r: RuleSpec, body: dict[str, Any], variables: dict[str, Any] | None = None
    ) -> None:
        """Part of the rules get what production rules carry; deterministic per rule name."""
        if not self.ops:
            return
        h = int(hashlib.sha256(r.name.encode()).hexdigest()[:8], 16) % 100
        src = self.zone_of(r.src, r.src_literals)
        dst = self.zone_of(r.dst, r.dst_literals)
        z_src, z_dst = self._ref("zones", f"Z_{src}"), self._ref("zones", f"Z_{dst}")
        if h < 65 and z_src and z_dst and src != dst:
            body["sourceZones"] = {"objects": [z_src]}
            body["destinationZones"] = {"objects": [z_dst]}
        allow = r.action == "ALLOW"
        tier_ips = self._ref("ips", "DF-IPS") if dst else None
        if "ipsPolicy" in body and tier_ips:
            body["ipsPolicy"] = tier_ips
        elif allow and "ipsPolicy" in body and dst == "GOLD" and h % 7 == 0:
            body["ipsPolicy"] = self._ref("ips", "DF-IPS-LEGACY-DETECT") or body["ipsPolicy"]
        elif allow and tier_ips and variables is not None and h < 40:
            # About 40% of the allow rules carry the organisation's IPS; the rest is the mess.
            body["ipsPolicy"] = tier_ips
            body["variableSet"] = {
                "id": variables["id"],
                "name": variables["name"],
                "type": "VariableSet",
            }
        file_policy = self._ref("policies", "DF-FILE-MALWARE")
        inspected = allow and "ipsPolicy" in body and dst in ("GOLD", "SILVER")
        if file_policy and inspected and h % 3 == 0:
            body["filePolicy"] = file_policy
        dept = next(
            (d for d in SGT_BY_DEPT for n in r.src if f"_{d}_" in n or n.endswith(f"_{d}")),
            None,
        )
        if dept and h >= 80:
            sgt = self._ref("objects", SGT_BY_DEPT[dept])
            if sgt:
                body["sourceSecurityGroupTags"] = {"objects": [sgt]}
        extras = {
            90: ("vlanTags", "objects", "VLAN_USERS"),
            91: ("vlanTags", "objects", "VLANGRP_DC"),
            92: ("urls", "objects", "URL_PORTAL"),
            93: ("urls", "objects", "URLGRP_BUSINESS"),
            94: ("timeRangeObjects", None, "TR_MAINT_WINDOW"),
            95: ("timeRangeObjects", None, "TR_BUSINESS_HOURS"),
        }
        if h in extras:
            field, key, name = extras[h]
            ref = self._ref("objects", name)
            if ref:
                body[field] = [ref] if key is None else {key: [ref]}
        if h == 96 and allow:
            echo = self._ref("objects", "ICMP_ECHO")
            if echo:
                body.setdefault("destinationPorts", {}).setdefault("objects", []).append(echo)

    async def load(self, limit: int, do_deploy: bool) -> None:
        self.write_assets()
        await self.objects()
        await self.dynamic_objects()
        prefilter = await self.prefilter()
        for name, rules in self.sc.policies.items():
            pid = await self.ensure_policy(name)
            await self.link_prefilter(pid, prefilter)
            # Loader.rules works on one policy: point it at this one, keep each policy's names.
            self.policy_name, self.sc.rules = name, rules
            self.m["rules"] = self.m["policies"].setdefault(name, {})
            await self.rules(limit, do_deploy)
            log(f"policy {name}: {len(self.m['rules'])} rules")
        self.save()


async def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("action", choices=("wipe", "load"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--work", type=Path, default=Path("/work"))
    parser.add_argument("--objects", type=int, default=8_000)
    parser.add_argument("--rules", type=int, default=2_000, help="rules per policy")
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--deploy-limit", type=int, default=1000, help="rules per chunk")
    parser.add_argument("--no-deploy", action="store_true")
    parser.add_argument("--yes-wipe-lab", action="store_true")
    args = parser.parse_args()
    if not args.yes_wipe_lab:
        print("refusing to touch the FMC without --yes-wipe-lab", file=sys.stderr)
        return 2
    password = os.environ.pop("DF_LAB_PASSWORD", "") or sys.stdin.readline().rstrip("\n")
    if not password:
        print("no password (DF_LAB_PASSWORD or stdin)", file=sys.stderr)
        return 2
    secret = bytearray(password.encode())
    del password
    args.work.mkdir(parents=True, exist_ok=True)
    scenario = build_policies(args.seed, objects=args.objects, rules=args.rules)
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
            run = DryRun(fmc, args.work, scenario)
            if args.action == "wipe":
                await run.wipe(not args.no_deploy)
            else:
                await run.load(args.deploy_limit, not args.no_deploy)
            log(f"{args.action} done")
    except FmcError as exc:
        print(f"FMC error: {exc.code}: {getattr(exc, 'description', '') or exc}", file=sys.stderr)
        return 1
    finally:
        secret[:] = b"\0" * len(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
