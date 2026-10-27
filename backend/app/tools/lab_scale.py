"""Load the large lab scenario (app.tools.lab_scenario) into a LAB FMC, deploying as it goes.

Only for lab systems — it WRITES to the FMC and DEPLOYS to its devices::

    docker run --rm -e DF_LAB_PASSWORD --add-host firepower:<ip> \\
        -v <fmc-cert.pem>:/ca.pem:ro -v <work dir>:/work doctor-firewall/api:dev \\
        python -m app.tools.lab_scale --host firepower --user admin --ca /ca.pem \\
        --policy FTDv-Cluster --deploy-limit 100 --yes-write-to-lab [--cleanup]

* Objects are created with the FMC bulk API (up to 1000 per request), members before groups.
* Rules are created in chunks of ``--deploy-limit`` (the per-deploy change budget: never more
  changes than that reach the devices at once); each chunk is deployed and the deployment
  awaited before the next one.
* Progress is saved in ``/work/manifest.json`` after every step: re-running resumes, and
  ``--cleanup`` removes exactly what the manifest lists (rules first, then objects, then a
  deployment). ``/work/assets.csv`` is the doctrine asset table for the scenario.
* The password comes from ``DF_LAB_PASSWORD`` (or stdin) and is never printed or stored.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from app.enforce.executor import BatchError, deploy
from app.fmc.adapters import select_adapter
from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError, FmcWriteRejectedError
from app.fmc.probe import server_version
from app.tools.lab_scenario import RuleSpec, Scenario, build

MARK = "df-lab-scale"
BULK = 1000
FMC_TYPES = {
    "hosts": "Host",
    "networks": "Network",
    "ranges": "Range",
    "fqdns": "FQDN",
    "protocolportobjects": "ProtocolPortObject",
    "networkgroups": "NetworkGroup",
    "portobjectgroups": "PortObjectGroup",
}
LEAVES = ("hosts", "networks", "ranges", "fqdns", "protocolportobjects")


def log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


class Loader:
    def __init__(self, fmc: FmcSession, work: Path, scenario: Scenario, policy: str) -> None:
        self.fmc = fmc
        self.adapter = select_adapter("10.1")
        self.work = work
        self.sc = scenario
        self.policy_name = policy
        self.manifest_path = work / "manifest.json"
        self.m: dict[str, Any] = {
            "objects": {},
            "rules": {},
            "chunks_deployed": 0,
            "categories": [],
        }
        if self.manifest_path.is_file():
            self.m.update(json.loads(self.manifest_path.read_text(encoding="utf-8")))

    def save(self) -> None:
        tmp = self.manifest_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.m, indent=1), encoding="utf-8")
        tmp.replace(self.manifest_path)

    def path(self, suffix: str) -> str:
        return f"/api/fmc_config/v1/domain/{self.fmc.domain_uuid}{suffix}"

    async def all(
        self, suffix: str, params: dict[str, str | int] | None = None
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        async for _offset, page in self.fmc.iter_pages(self.path(suffix), params=params):
            items.extend(page)
        return items

    def ref(self, name: str) -> dict[str, str]:
        found = self.m["objects"][name]
        return {"id": found["id"], "type": found["type"], "name": name}

    # ---- objects

    def body(self, name: str) -> dict[str, Any]:
        o = self.sc.objects[name]
        body: dict[str, Any] = {"name": name, "type": FMC_TYPES[o.resource], "description": MARK}
        if o.resource == "protocolportobjects":
            proto, _, port = (o.value or "").partition("/")
            body.update(protocol=proto, port=port)
        elif o.resource in ("networkgroups", "portobjectgroups"):
            body["objects"] = [self.ref(m) for m in o.members]
        else:
            body["value"] = o.value
        return body

    async def objects(self) -> None:
        existing: dict[str, dict[str, str]] = {}
        for resource in FMC_TYPES:
            for item in await self.all(f"/object/{resource}"):
                existing[item["name"]] = {"id": item["id"], "type": item["type"]}
        waves: list[tuple[str, list[str]]] = [
            (r, [n for n, o in self.sc.objects.items() if o.resource == r]) for r in LEAVES
        ]
        waves.append(
            (
                "portobjectgroups",
                [n for n, o in self.sc.objects.items() if o.resource == "portobjectgroups"],
            )
        )
        depth = max(
            (o.depth for o in self.sc.objects.values() if o.resource == "networkgroups"), default=0
        )
        for level in range(1, depth + 1):
            waves.append(
                (
                    "networkgroups",
                    [
                        n
                        for n, o in self.sc.objects.items()
                        if o.resource == "networkgroups" and o.depth == level
                    ],
                )
            )
        for resource, names in waves:
            todo = []
            for name in names:
                if name in self.m["objects"]:
                    continue
                if name in existing:  # present already (an earlier run lost its manifest)
                    self.m["objects"][name] = {**existing[name], "ours": False}
                    continue
                todo.append(name)
            for start in range(0, len(todo), BULK):
                chunk = todo[start : start + BULK]
                await self.create_bulk(resource, chunk)
                self.save()
            log(f"{resource}: {len(names)} in scenario, {len(todo)} created")

    async def lookup(self, resource: str, name: str) -> dict[str, str] | None:
        """An object by name — case-insensitive like the FMC (a built-in ``TCP_high_ports``
        blocks ``TCP_HIGH_PORTS``); port names share one name space across port types."""
        listings = (
            ["/object/ports"] if resource in ("protocolportobjects", "portobjectgroups") else []
        )
        for suffix in [f"/object/{resource}", *listings]:
            for item in await self.all(suffix, {"filter": f"nameOrValue:{name}"}):
                if str(item.get("name", "")).lower() == name.lower():  # FMC names ignore case
                    return {"id": str(item["id"]), "type": str(item["type"])}
        return None

    async def create_bulk(self, resource: str, names: list[str]) -> None:
        bodies = [self.body(n) for n in names]
        try:
            made = await self.fmc.write_json(
                "POST", self.path(f"/object/{resource}"), bodies, {"bulk": "true"}
            )
        except FmcWriteRejectedError as exc:
            log(f"  bulk {resource} refused ({exc.description[:120]}); creating one by one")
            for body in bodies:
                try:
                    one = await self.fmc.write_json("POST", self.path(f"/object/{resource}"), body)
                    self.m["objects"][one["name"]] = {
                        "id": one["id"],
                        "type": one["type"],
                        "ours": True,
                    }
                except FmcWriteRejectedError as single:
                    found = await self.lookup(resource, str(body["name"]))
                    if found is not None:  # same name already there (e.g. a built-in): use it
                        self.m["objects"][str(body["name"])] = {**found, "ours": False}
                        log(f"  {body['name']}: exists already, used as is")
                    else:
                        log(f"  skipped {body['name']}: {single.description[:120]}")
            return
        items = made.get("items", []) if isinstance(made, dict) else made or []
        for item in items:
            self.m["objects"][item["name"]] = {"id": item["id"], "type": item["type"], "ours": True}

    # ---- rules

    async def policy(self) -> str:
        for item in await self.all("/policy/accesspolicies"):
            if item["name"] == self.policy_name:
                return str(item["id"])
        raise SystemExit(f"access policy {self.policy_name!r} not found")

    def rule_body(
        self, r: RuleSpec, ips: dict[str, Any], variables: dict[str, Any] | None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "name": r.name,
            "type": "AccessRule",
            "action": r.action,
            "enabled": r.enabled,
            "sendEventsToFMC": True,
        }
        blocking = r.action in ("BLOCK", "BLOCK_RESET")
        body["logBegin"], body["logEnd"] = blocking, not blocking
        for names, literals, field in (
            (r.src, r.src_literals, "sourceNetworks"),
            (r.dst, r.dst_literals, "destinationNetworks"),
        ):
            part: dict[str, Any] = {}
            if names:
                part["objects"] = [self.ref(n) for n in names if n in self.m["objects"]]
            if literals:
                part["literals"] = [
                    {"type": "Network" if "/" in v else "Host", "value": v} for v in literals
                ]
            if part:
                body[field] = part
        if r.ports:
            body["destinationPorts"] = {
                "objects": [self.ref(p) for p in r.ports if p in self.m["objects"]]
            }
        if r.ips and r.action == "ALLOW" and r.ips in ips and variables is not None:
            policy = ips[r.ips]
            body["ipsPolicy"] = {
                "id": policy["id"],
                "name": policy["name"],
                "type": "IntrusionPolicy",
            }
            body["variableSet"] = {
                "id": variables["id"],
                "name": variables["name"],
                "type": "VariableSet",
            }
        return body

    async def rules(self, limit: int, do_deploy: bool, max_chunks: int = 0) -> None:
        pid = await self.policy()
        existing = {
            r["name"]: r["id"] for r in await self.all(f"/policy/accesspolicies/{pid}/accessrules")
        }
        categories = {c["name"] for c in await self.all(f"/policy/accesspolicies/{pid}/categories")}
        for name in dict.fromkeys(r.category for r in self.sc.rules):
            if name not in categories:
                await self.fmc.write_json(
                    "POST",
                    self.path(f"/policy/accesspolicies/{pid}/categories"),
                    {"name": name, "type": "Category"},
                    {"section": "mandatory"},
                )
                self.m["categories"].append(name)
                log(f"category {name}")
        self.save()
        ips = {p["name"]: p for p in await self.all("/policy/intrusionpolicies")}
        variables = next(
            (v for v in await self.all("/object/variablesets") if v["name"] == "Default-Set"), None
        )
        todo = [
            r for r in self.sc.rules if r.name not in self.m["rules"] and r.name not in existing
        ]
        for name in (
            r.name for r in self.sc.rules if r.name in existing and r.name not in self.m["rules"]
        ):
            self.m["rules"][name] = existing[name]
        log(f"rules: {len(self.sc.rules)} in scenario, {len(todo)} to create in chunks of {limit}")
        for number, start in enumerate(range(0, len(todo), limit), start=1):
            if max_chunks and number > max_chunks:
                log(f"stopping after {max_chunks} chunk(s) (--max-chunks); re-run to continue")
                return
            chunk = todo[start : start + limit]
            # One bulk request per category run (the category is a query parameter).
            i = 0
            while i < len(chunk):
                category = chunk[i].category
                run = []
                while i < len(chunk) and chunk[i].category == category:
                    run.append(chunk[i])
                    i += 1
                made = await self.fmc.write_json(
                    "POST",
                    self.path(f"/policy/accesspolicies/{pid}/accessrules"),
                    [self.rule_body(r, ips, variables) for r in run],
                    {"bulk": "true", "category": category},  # never with "section"
                )
                items = made.get("items", []) if isinstance(made, dict) else made or []
                for item in items:
                    self.m["rules"][item["name"]] = item["id"]
            self.save()
            done = len(self.m["rules"])
            log(f"rules created: {done}/{len(self.sc.rules)}")
            if do_deploy:
                await self.deploy_now(f"chunk {number}")
                self.m["chunks_deployed"] = self.m.get("chunks_deployed", 0) + 1
                self.save()

    async def deploy_now(self, label: str) -> None:
        listing = await self.fmc.get_json(
            self.path("/deployment/deployabledevices"), {"expanded": "true"}
        )
        targets = {
            str(item["device"]["id"])
            for item in (listing or {}).get("items", [])
            if "device" in item
        }
        if not targets:
            log(f"deploy {label}: nothing pending")
            return
        started = time.monotonic()
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
            raise SystemExit(f"deploy {label} failed: {exc}") from exc
        log(f"deploy {label}: done in {time.monotonic() - started:.0f}s (task {task})")

    # ---- cleanup

    async def cleanup(self, do_deploy: bool) -> None:
        pid = await self.policy()
        ids = list(self.m["rules"].values())
        for start in range(0, len(ids), 50):
            chunk = ids[start : start + 50]
            try:
                await self.fmc.write_json(
                    "DELETE",
                    self.path(f"/policy/accesspolicies/{pid}/accessrules"),
                    None,
                    {"bulk": "true", "filter": "ids:" + ",".join(chunk)},
                )
            except FmcWriteRejectedError:
                for rid in chunk:
                    await self.fmc.write_json(
                        "DELETE", self.path(f"/policy/accesspolicies/{pid}/accessrules/{rid}")
                    )
            log(f"rules deleted: {min(start + 50, len(ids))}/{len(ids)}")
        self.m["rules"] = {}
        self.save()
        for name in self.m.get("categories", []):
            for c in await self.all(f"/policy/accesspolicies/{pid}/categories"):
                if c["name"] == name:
                    await self.fmc.write_json(
                        "DELETE", self.path(f"/policy/accesspolicies/{pid}/categories/{c['id']}")
                    )
        self.m["categories"] = []
        self.save()
        ours = [(n, o) for n, o in self.m["objects"].items() if o.get("ours")]
        depth = {n: self.sc.objects[n].depth if n in self.sc.objects else 0 for n, _ in ours}
        resource_of = {v: k for k, v in FMC_TYPES.items()}
        for name, obj in sorted(ours, key=lambda item: -depth[item[0]]):
            resource = resource_of[obj["type"]]
            try:
                await self.fmc.write_json("DELETE", self.path(f"/object/{resource}/{obj['id']}"))
            except FmcWriteRejectedError as exc:
                log(f"  kept {name}: {exc.description[:100]}")
                continue
            del self.m["objects"][name]
            if len(self.m["objects"]) % 500 == 0:
                self.save()
                log(f"objects left: {len(self.m['objects'])}")
        self.save()
        if do_deploy:
            await self.deploy_now("cleanup")

    def write_assets(self) -> None:
        path = self.work / "assets.csv"
        columns = [
            "network",
            "system",
            "tier",
            "system_type",
            "user_type",
            "ports",
            "notes",
            "asset",
            "asset_kind",
        ]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns)
            writer.writeheader()
            for row in self.sc.assets:
                writer.writerow({c: row.get(c, "") for c in columns})
        log(f"asset table: {path} ({len(self.sc.assets)} rows)")


async def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--work", type=Path, default=Path("/work"))
    parser.add_argument("--objects", type=int, default=10_000)
    parser.add_argument("--rules", type=int, default=3_000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--deploy-limit", type=int, default=100, help="changes per deployment")
    parser.add_argument("--no-deploy", action="store_true")
    parser.add_argument("--max-chunks", type=int, default=0, help="stop after N rule chunks")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument(
        "--deploy-only", action="store_true", help="deploy pending changes, nothing else"
    )
    parser.add_argument("--yes-write-to-lab", action="store_true")
    args = parser.parse_args()
    if not args.yes_write_to_lab:
        print("refusing to write without --yes-write-to-lab", file=sys.stderr)
        return 2
    if not 1 <= args.deploy_limit <= 1000:
        print("--deploy-limit must be 1..1000", file=sys.stderr)
        return 2
    password = os.environ.pop("DF_LAB_PASSWORD", "") or sys.stdin.readline().rstrip("\n")
    if not password:
        print("no password (DF_LAB_PASSWORD or stdin)", file=sys.stderr)
        return 2
    secret = bytearray(password.encode())
    del password
    args.work.mkdir(parents=True, exist_ok=True)
    scenario = build(args.seed, args.objects, args.rules)
    try:
        async with FmcSession(
            host=args.host,
            port=args.port,
            username=args.user,
            password_provider=lambda: bytearray(secret),
            ssl_context=build_ssl_context(args.ca),
            timeout=300,
            throttle=ThrottlePolicy(requests_per_minute=100),
        ) as fmc:
            log(f"FMC {await server_version(fmc)}")
            loader = Loader(fmc, args.work, scenario, args.policy)
            if args.deploy_only:
                await loader.deploy_now("pending changes")
            elif args.cleanup:
                await loader.cleanup(not args.no_deploy)
            else:
                loader.write_assets()
                await loader.objects()
                await loader.rules(args.deploy_limit, not args.no_deploy, args.max_chunks)
                log("scenario loaded")
    except FmcError as exc:
        print(f"FMC error: {exc.code}: {getattr(exc, 'description', '') or exc}", file=sys.stderr)
        return 1
    finally:
        secret[:] = b"\0" * len(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
