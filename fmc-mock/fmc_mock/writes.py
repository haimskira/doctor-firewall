"""FMC 10.1 configuration writes and deployment, emulated for the enforcement tests.

Behaviour the writer must cope with, as on a real FMC:

* object / rule GET-by-id, POST, PUT (full replacement), DELETE;
* duplicate names in a name space are rejected (400);
* an object still referenced by a rule, a group or a route cannot be deleted (400);
* references to unknown objects are rejected (400);
* rules are positioned with ``insertAfter`` / ``insertBefore`` (rule index) and renumbered;
* writes only mark devices as needing a deploy; ``deploymentrequests`` starts an asynchronous
  task polled at ``/job/taskstatuses/{id}`` (Deploying -> Deployed);
* one write at a time per server (enforced by :mod:`fmc_mock.limits`).

Test-only endpoints (``/mock/reset``, ``/mock/faults``) exist only in this emulator.
"""

from __future__ import annotations

import itertools
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, fields
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from fmc_mock.cli import show_route
from fmc_mock.resources import CONFIG, _error
from fmc_mock.seed import FmcData

Json = dict[str, Any]

OBJECT_TYPES = {
    "hosts": "Host",
    "networks": "Network",
    "ranges": "Range",
    "protocolportobjects": "ProtocolPortObject",
    "networkgroups": "NetworkGroup",
    "portobjectgroups": "PortObjectGroup",
}
# Name spaces in which object names must be unique.
NETWORK_FAMILY = ("hosts", "networks", "ranges", "fqdns", "networkgroups")
PORT_FAMILY = ("protocolportobjects", "portobjectgroups", "icmpv4objects", "icmpv6objects")
RULE_STORES = {"accessrules": "AccessRule", "prefilterrules": "PrefilterRule"}
NOT_OBJECTS = frozenset(
    {
        "id",
        "metadata",
        "links",
        "ipsPolicy",
        "filePolicy",
        "variableSet",
        "logFiles",
        "applications",
        "users",
    }
)


@dataclass
class WriteState:
    pending: set[str] = field(default_factory=set)  # HA pair ids needing a deploy
    tasks: dict[str, Json] = field(default_factory=dict)
    faults: Json = field(default_factory=dict)
    writes: int = 0


def _walk_ids(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        if "id" in value and isinstance(value["id"], str) and "type" in value:
            yield value["id"]
        for v in value.values():
            yield from _walk_ids(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_ids(v)


def build_write_router(
    data: FmcData,
    domain_uuid: str,
    token_ok: Callable[[Request], bool],
    regenerate: Callable[[], FmcData],
) -> tuple[APIRouter, WriteState]:
    router = APIRouter()
    state = WriteState()

    def guard(request: Request, domain: str) -> Response | None:
        if not token_ok(request):
            return _error(401, "Access token invalid.")
        if domain != domain_uuid:
            return _error(404, "Domain not found")
        return None

    def all_objects() -> dict[str, Json]:
        return {o["id"]: o for items in data.objects.values() for o in items}

    def rules_of(policy_id: str, store: str) -> list[Json] | None:
        if store == "accessrules":
            return data.rules.get(policy_id)
        return data.policy_rules.get(("prefilterpolicies", policy_id, store))

    def all_rule_lists() -> Iterator[list[Json]]:
        yield from data.rules.values()
        yield from data.policy_rules.values()

    def in_use(object_id: str) -> bool:
        for rules in all_rule_lists():
            for r in rules:
                if object_id in set(
                    _walk_ids({k: v for k, v in r.items() if k not in ("id", "metadata")})
                ):
                    return True
        for items in data.objects.values():
            for o in items:
                if o["id"] != object_id and any(
                    m.get("id") == object_id for m in o.get("objects", [])
                ):
                    return True
        return any(object_id in set(_walk_ids(routes)) for routes in data.static_routes.values())

    def unknown_refs(body: Json, ignore: set[str]) -> list[str]:
        known = all_objects()
        missing = []
        for key, value in body.items():
            # Policies and applications are not configuration objects of this emulator.
            if key in NOT_OBJECTS:
                continue
            for oid in _walk_ids(value):
                if oid not in known and oid not in ignore:
                    missing.append(oid)
        return missing

    def duplicate_name(resource: str, name: str, own_id: str | None) -> bool:
        family = NETWORK_FAMILY if resource in NETWORK_FAMILY else PORT_FAMILY
        return any(
            o["name"].lower() == name.lower() and o["id"] != own_id
            for res in family
            for o in data.objects.get(res, [])
        )

    def mark_pending(policy_id: str | None = None) -> None:
        """Devices that need a deploy: all for shared objects, else those using the policy."""
        state.writes += 1
        access_ids = {policy_id} if policy_id is not None else set()
        if policy_id is not None:
            access_ids |= {
                p["id"]
                for p in data.policies
                if p.get("prefilterPolicySetting", {}).get("id") == policy_id
            }
        for ha in data.ha_pairs:
            if policy_id is None:
                state.pending.add(ha["id"])
                continue
            members = {ha["primary"]["id"], ha["secondary"]["id"]}
            if any(
                d["id"] in members and d.get("accessPolicy", {}).get("id") in access_ids
                for d in data.devices
            ):
                state.pending.add(ha["id"])

    def fault(name: str) -> bool:
        return bool(state.faults.get(name))

    def fail_write(text: str) -> bool:
        needle = state.faults.get("fail_write_on")
        return isinstance(needle, str) and needle != "" and needle in text

    # ---------------------------------------------------------------- objects

    def object_body(resource: str, body: Json, own_id: str | None) -> Json | Response:
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("name"), str)
            or not body["name"].strip()
        ):
            return _error(400, "name is required")
        if body.get("type") != OBJECT_TYPES[resource]:
            return _error(400, f"type must be {OBJECT_TYPES[resource]}")
        if duplicate_name(resource, body["name"], own_id):
            return _error(400, f"Duplicate name: {body['name']}")
        if fail_write(body["name"]):
            return _error(400, "Injected failure")
        missing = unknown_refs({"objects": body.get("objects", [])}, set())
        if missing:
            return _error(400, f"Unknown object(s): {', '.join(missing[:3])}")
        return body

    for resource in OBJECT_TYPES:

        def bind(resource: str = resource) -> None:
            path = CONFIG + f"/object/{resource}"

            @router.get(path + "/{object_id}", name=f"get:{resource}")
            async def _get(request: Request, domain: str, object_id: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                item = next(
                    (o for o in data.objects.get(resource, []) if o["id"] == object_id), None
                )
                return JSONResponse(item) if item is not None else _error(404, "Object not found")

            @router.post(path, name=f"post:{resource}")
            async def _post(request: Request, domain: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                body = object_body(resource, await request.json(), None)
                if isinstance(body, Response):
                    return body
                item = {**body, "id": str(uuid.uuid4())}
                data.objects.setdefault(resource, []).append(item)
                mark_pending()
                return JSONResponse(item, status_code=201)

            @router.put(path + "/{object_id}", name=f"put:{resource}")
            async def _put(request: Request, domain: str, object_id: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                items = data.objects.get(resource, [])
                pos = next((i for i, o in enumerate(items) if o["id"] == object_id), None)
                if pos is None:
                    return _error(404, "Object not found")
                if ((items[pos].get("metadata") or {}).get("readOnly") or {}).get("state"):
                    return _error(400, "System objects cannot be modified or deleted")
                body = object_body(resource, await request.json(), object_id)
                if isinstance(body, Response):
                    return body
                if body.get("id") != object_id:
                    return _error(400, "id mismatch")
                items[pos] = dict(body)
                mark_pending()
                return JSONResponse(items[pos])

            @router.delete(path + "/{object_id}", name=f"delete:{resource}")
            async def _delete(request: Request, domain: str, object_id: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                items = data.objects.get(resource, [])
                pos = next((i for i, o in enumerate(items) if o["id"] == object_id), None)
                if pos is None:
                    return _error(404, "Object not found")
                if ((items[pos].get("metadata") or {}).get("readOnly") or {}).get("state"):
                    return _error(400, "System objects cannot be modified or deleted")
                if fail_write(items[pos]["name"]):
                    return _error(400, "Injected failure")
                if in_use(object_id):
                    return _error(400, "The object is in use and cannot be deleted")
                item = items.pop(pos)
                mark_pending()
                return JSONResponse(item)

        bind()

    # ---------------------------------------------------------------- rules

    def ref_id(value: Any) -> str | None:
        return str(value["id"]) if isinstance(value, dict) and "id" in value else None

    def inspection_error(body: Json) -> Response | None:
        """The FMC's checks on the intrusion / file policy of an access rule."""
        ips, file, variables = (
            ref_id(body.get("ipsPolicy")),
            ref_id(body.get("filePolicy")),
            ref_id(body.get("variableSet")),
        )
        policies = {
            kind: {p["id"] for p in data.policy_lists.get(kind, [])}
            for kind in ("intrusionpolicies", "filepolicies")
        }
        if body.get("ipsPolicy") is not None:
            if ips not in policies["intrusionpolicies"]:
                return _error(400, "Invalid intrusion policy")
            if body.get("action") != "ALLOW":
                return _error(400, "An intrusion policy requires the Allow action")
            if variables not in {v["id"] for v in data.variable_sets}:
                return _error(400, "A variable set is required with an intrusion policy")
        if body.get("filePolicy") is not None:
            if file not in policies["filepolicies"]:
                return _error(400, "Invalid file policy")
            if body.get("action") != "ALLOW":
                return _error(400, "A file policy requires the Allow action")
        return None

    def renumber(rules: list[Json]) -> None:
        for index, r in enumerate(rules, start=1):
            r.setdefault("metadata", {})["ruleIndex"] = index

    for store, rule_type in RULE_STORES.items():
        policy_path = "accesspolicies" if store == "accessrules" else "prefilterpolicies"

        def bind_rules(
            store: str = store, rule_type: str = rule_type, policy_path: str = policy_path
        ) -> None:
            base = CONFIG + f"/policy/{policy_path}/{{policy_id}}/{store}"

            def find(policy_id: str, rule_id: str) -> tuple[list[Json] | None, int | None]:
                rules = rules_of(policy_id, store)
                if rules is None:
                    return None, None
                return rules, next((i for i, r in enumerate(rules) if r["id"] == rule_id), None)

            def check(body: Any, rules: list[Json], own_id: str | None) -> Response | None:
                if (
                    not isinstance(body, dict)
                    or not isinstance(body.get("name"), str)
                    or not body["name"].strip()
                ):
                    return _error(400, "name is required")
                if body.get("type") != rule_type:
                    return _error(400, f"type must be {rule_type}")
                if any(r["name"] == body["name"] and r["id"] != own_id for r in rules):
                    return _error(400, f"Duplicate rule name: {body['name']}")
                if fail_write(body["name"]):
                    return _error(400, "Injected failure")
                missing = unknown_refs(body, set())
                if missing:
                    return _error(400, f"Unknown object(s): {', '.join(missing[:3])}")
                return inspection_error(body)

            @router.get(base + "/{rule_id}", name=f"get:{store}")
            async def _get(request: Request, domain: str, policy_id: str, rule_id: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                rules, pos = find(policy_id, rule_id)
                if rules is None or pos is None:
                    return _error(404, "Rule not found")
                return JSONResponse(rules[pos])

            @router.post(base, name=f"post:{store}")
            async def _post(request: Request, domain: str, policy_id: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                rules = rules_of(policy_id, store)
                if rules is None:
                    return _error(404, "Policy not found")
                body = await request.json()
                if (bad := check(body, rules, None)) is not None:
                    return bad
                params = request.query_params
                if "section" in params and "category" in params:
                    return _error(
                        400, "query parameter section and category are not allowed together"
                    )
                try:
                    if "insertAfter" in params:
                        position = int(params["insertAfter"])
                    elif "insertBefore" in params:
                        position = int(params["insertBefore"]) - 1
                    else:
                        position = len(rules)
                except ValueError:
                    return _error(400, "insertAfter / insertBefore must be a rule index")
                if not 0 <= position <= len(rules):
                    return _error(400, "rule index out of range")
                meta = dict(body.get("metadata") or {})
                meta["section"] = params.get("section", meta.get("section", "Default")).capitalize()
                meta["category"] = params.get("category", meta.get("category", "--Undefined--"))
                item = {**body, "id": str(uuid.uuid4()), "metadata": meta}
                rules.insert(position, item)
                renumber(rules)
                mark_pending(policy_id)
                return JSONResponse(item, status_code=201)

            @router.put(base + "/{rule_id}", name=f"put:{store}")
            async def _put(request: Request, domain: str, policy_id: str, rule_id: str) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                rules, pos = find(policy_id, rule_id)
                if rules is None or pos is None:
                    return _error(404, "Rule not found")
                body = await request.json()
                if (bad := check(body, rules, rule_id)) is not None:
                    return bad
                if body.get("id") != rule_id:
                    return _error(400, "id mismatch")
                rules[pos] = {**body, "metadata": rules[pos].get("metadata", {})}
                mark_pending(policy_id)
                return JSONResponse(rules[pos])

            @router.delete(base + "/{rule_id}", name=f"delete:{store}")
            async def _delete(
                request: Request, domain: str, policy_id: str, rule_id: str
            ) -> Response:
                if (resp := guard(request, domain)) is not None:
                    return resp
                rules, pos = find(policy_id, rule_id)
                if rules is None or pos is None:
                    return _error(404, "Rule not found")
                if fail_write(rules[pos]["name"]):
                    return _error(400, "Injected failure")
                item = rules.pop(pos)
                renumber(rules)
                mark_pending(policy_id)
                return JSONResponse(item)

        bind_rules()

    # ---------------------------------------------------------------- deployment

    counter = itertools.count(1)

    @router.get(CONFIG + "/devices/devicerecords/{device_id}/operational/commands")
    async def commands(request: Request, domain: str, device_id: str) -> Response:
        """Read-only device CLI (FMC 7.4.1+): only ``show route`` is offered here."""
        if (resp := guard(request, domain)) is not None:
            return resp
        if not any(d["id"] == device_id for d in data.devices):
            return _error(404, "Device not found")
        command = request.query_params.get("command", "")
        if fault("cli_unsupported") or command != "show route":
            return _error(400, f"The command '{command[:40]}' is not supported.")
        if fault("device_down"):
            return _error(
                500, "SFTunnelException: Cannot establish a connection with the threat defense"
            )
        source = device_id
        if fault("cli_mixup"):  # the FMC answering with a device of ANOTHER cluster
            own = {device_id}
            for pair in data.ha_pairs:
                units = {pair["primary"]["id"], pair["secondary"]["id"]}
                if device_id in units:
                    own |= units
            source = next((d for d in data.interfaces if d not in own), device_id)
        output = show_route(
            data.interfaces.get(source, {}), data.static_routes.get(source, []), all_objects()
        )
        return JSONResponse(
            {
                "items": [{"type": "Command", "commandInput": command, "commandOutput": output}],
                "paging": {"offset": 0, "limit": 1, "count": 1, "pages": 1},
            }
        )

    @router.get(CONFIG + "/deployment/deployabledevices")
    async def deployable(request: Request, domain: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        version = str(int(time.time() * 1000))
        items = [
            {
                "type": "DeployableDevice",
                "name": ha["name"],
                "version": version,
                "canBeDeployed": True,
                "device": {"id": ha["id"], "type": "DeviceHAPair", "name": ha["name"]},
            }
            for ha in data.ha_pairs
            if ha["id"] in state.pending
        ]
        body: Json = {
            "links": {"self": str(request.url)},
            "paging": {"offset": 0, "limit": 25, "count": len(items), "pages": 1},
        }
        if items:
            body["items"] = items
        return JSONResponse(body)

    @router.post(CONFIG + "/deployment/deploymentrequests")
    async def deploy(request: Request, domain: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        body = await request.json()
        devices = body.get("deviceList") if isinstance(body, dict) else None
        if body.get("type") != "DeploymentRequest" or not isinstance(devices, list) or not devices:
            return _error(400, "deviceList is required")
        unknown = [d for d in devices if d not in state.pending]
        if unknown:
            return _error(400, f"Device(s) not deployable: {', '.join(unknown[:3])}")
        task_id = f"task-{next(counter)}"
        state.tasks[task_id] = {"polls": 0, "devices": devices, "fail": fault("deploy_fail")}
        for d in devices:
            state.pending.discard(d)
        return JSONResponse(
            {
                "type": "DeploymentRequest",
                "version": body.get("version"),
                "deviceList": devices,
                "metadata": {"task": {"id": task_id, "type": "TaskStatus"}},
            },
            status_code=202,
        )

    @router.get(CONFIG + "/job/taskstatuses/{task_id}")
    async def task_status(request: Request, domain: str, task_id: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        task = state.tasks.get(task_id)
        if task is None:
            return _error(404, "Task not found")
        task["polls"] += 1
        status_text = (
            "Deploying" if task["polls"] < 2 else ("Failed" if task["fail"] else "Deployed")
        )
        return JSONResponse(
            {"id": task_id, "type": "TaskStatus", "status": status_text, "message": status_text}
        )

    # ---------------------------------------------------------------- test-only controls

    @router.post("/mock/reset")
    async def reset(request: Request) -> Response:
        if not token_ok(request):
            return _error(401, "Access token invalid.")
        fresh = regenerate()
        for f in fields(FmcData):
            setattr(data, f.name, getattr(fresh, f.name))
        state.pending.clear()
        state.tasks.clear()
        state.faults.clear()
        state.writes = 0
        return Response(status_code=204)

    @router.post("/mock/faults")
    async def faults(request: Request) -> Response:
        if not token_ok(request):
            return _error(401, "Access token invalid.")
        body = await request.json()
        if not isinstance(body, dict):
            return _error(400, "object expected")
        state.faults.clear()
        data.disabled.clear()
        if body.get("ise_disabled"):
            data.disabled.add("ise")
        state.faults.update(
            {
                k: v
                for k, v in body.items()
                if k
                in (
                    "deploy_fail",
                    "fail_write_on",
                    "cli_unsupported",
                    "device_down",
                    "cli_mixup",
                    "lost_answer_on",
                    "outage_on",
                )
            }
        )
        return JSONResponse({"faults": state.faults, "writes": state.writes})

    return router, state
