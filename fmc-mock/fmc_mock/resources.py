"""FMC 10.1 configuration resources with FMC paging semantics.

* ``offset`` / ``limit`` (default 25, maximum 1000; larger limits are rejected).
* ``expanded=true`` returns full objects; otherwise only id/name/type/links.
* The ``paging`` block carries ``offset, limit, count, pages`` and ``next`` links;
  an empty collection omits ``items`` entirely (as the real FMC does).
"""

from __future__ import annotations

import math
from collections.abc import Callable
from functools import partial
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from fmc_mock.seed import FmcData

Json = dict[str, Any]
CONFIG = "/api/fmc_config/v1/domain/{domain}"
MAX_LIMIT = 1000


def _error(status: int, text: str) -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "category": "FRAMEWORK",
                "messages": [{"description": text}],
                "severity": "ERROR",
            }
        },
        status_code=status,
    )


def _summary(item: Json, base: str) -> Json:
    return {
        "id": item["id"],
        "name": item.get("name", ""),
        "type": item.get("type", ""),
        "links": {"self": f"{base}/{item['id']}"},
    }


def page(request: Request, items: list[Json]) -> Response:
    try:
        offset = int(request.query_params.get("offset", "0"))
        limit = int(request.query_params.get("limit", "25"))
    except ValueError:
        return _error(400, "Invalid paging parameters")
    if offset < 0 or limit < 1 or limit > MAX_LIMIT:
        return _error(400, f"limit must be between 1 and {MAX_LIMIT}")
    expanded = request.query_params.get("expanded", "false").lower() == "true"
    base = str(request.url).split("?")[0]
    chunk = items[offset : offset + limit]
    body: Json = {"links": {"self": str(request.url)}}
    if chunk:
        body["items"] = [dict(i) if expanded else _summary(i, base) for i in chunk]
    paging: Json = {
        "offset": offset,
        "limit": limit if items else 0,  # as the FMC reports an empty collection
        "count": len(items),
        "pages": math.ceil(len(items) / limit) if items else 0,
    }
    if offset + limit < len(items):
        paging["next"] = [
            f"{base}?offset={offset + limit}&limit={limit}" + ("&expanded=true" if expanded else "")
        ]
    body["paging"] = paging
    return JSONResponse(body)


def _objects_of(data: FmcData, resource: str) -> list[Json]:
    return data.objects.get(resource, [])


def _policies_of(data: FmcData, resource: str) -> list[Json]:
    return data.policy_lists.get(resource, [])


def _interfaces_of(data: FmcData, kind: str, device_id: str) -> list[Json]:
    return data.interfaces.get(device_id, {}).get(kind, [])


def build_router(data: FmcData, domain_uuid: str, token_ok: Callable[[Request], bool]) -> APIRouter:
    router = APIRouter()

    def guard(request: Request, domain: str) -> Response | None:
        if not token_ok(request):
            return _error(401, "Access token invalid.")
        if domain != domain_uuid:
            return _error(404, "Domain not found")
        return None

    def collection(path: str, getter: Callable[[], list[Json]]) -> None:
        @router.get(CONFIG + path, name=f"list:{path}")
        async def _list(request: Request, domain: str) -> Response:
            return guard(request, domain) or page(request, getter())

    for resource in (
        "hosts",
        "networks",
        "ranges",
        "fqdns",
        "networkgroups",
        "protocolportobjects",
        "portobjectgroups",
        "icmpv4objects",
        "icmpv6objects",
        "securityzones",
        "securitygrouptags",
        "isesecuritygrouptags",
        "dynamicobjects",
        "urls",
        "urlgroups",
    ):
        if resource == "isesecuritygrouptags":
            continue  # below: refused while ISE is disabled
        collection(f"/object/{resource}", partial(_objects_of, data, resource))

    @router.get(CONFIG + "/object/isesecuritygrouptags", name="list:/object/isesecuritygrouptags")
    async def _ise_tags(request: Request, domain: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        if "ise" in data.disabled:
            return _error(
                422, "Request cannot be processed because Identity Service Engine is disabled"
            )
        return page(request, _objects_of(data, "isesecuritygrouptags"))

    @router.get(CONFIG + "/object/dynamicobjects/{object_id}/mappings")
    async def dynamic_mappings(request: Request, domain: str, object_id: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        if object_id not in data.dynamic_mappings:
            return _error(404, "Dynamic object not found")
        return page(request, [{"mapping": m} for m in data.dynamic_mappings[object_id]])

    collection("/object/variablesets", lambda: data.variable_sets)
    collection("/devices/devicerecords", lambda: data.devices)
    collection("/devicehapairs/ftddevicehapairs", lambda: data.ha_pairs)
    collection("/deviceclusters/ftddevicecluster", lambda: [])
    collection("/policy/accesspolicies", lambda: data.policies)
    collection("/assignment/policyassignments", lambda: data.assignments)

    @router.get(CONFIG + "/policy/accesspolicies/{policy_id}/accessrules")
    async def rules(request: Request, domain: str, policy_id: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        if policy_id not in data.rules:
            return _error(404, "Policy not found")
        return page(request, data.rules[policy_id])

    @router.get(CONFIG + "/policy/accesspolicies/{policy_id}/categories")
    async def categories(request: Request, domain: str, policy_id: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        if policy_id not in data.categories:
            return _error(404, "Policy not found")
        return page(request, data.categories[policy_id])

    @router.get(CONFIG + "/policy/accesspolicies/{policy_id}/operational/hitcounts")
    async def hitcounts(request: Request, domain: str, policy_id: str) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        flt = request.query_params.get("filter", "").strip('"')
        if not flt.startswith("deviceId:"):
            return _error(400, "filter deviceId:<uuid> is required")
        key = (policy_id, flt.removeprefix("deviceId:"))
        if key not in data.hitcounts:
            return _error(404, "No hit counts for this policy/device")
        return page(request, data.hitcounts[key])

    for resource in (
        "prefilterpolicies",
        "decryptionpolicies",
        "identitypolicies",
        "ftdnatpolicies",
        "intrusionpolicies",
        "filepolicies",
        "dnspolicies",
    ):
        collection(f"/policy/{resource}", partial(_policies_of, data, resource))

    @router.get(CONFIG + "/policy/{resource}/{policy_id}/{sub}")
    async def policy_rules(
        request: Request, domain: str, resource: str, policy_id: str, sub: str
    ) -> Response:
        if (resp := guard(request, domain)) is not None:
            return resp
        rules = data.policy_rules.get((resource, policy_id, sub))
        if rules is None:
            return _error(404, "Not found")
        return page(request, rules)

    def per_device(path: str, store: Callable[[str], list[Json] | None]) -> None:
        @router.get(CONFIG + "/devices/devicerecords/{device_id}" + path, name=f"dev:{path}")
        async def _dev(request: Request, domain: str, device_id: str) -> Response:
            if (resp := guard(request, domain)) is not None:
                return resp
            if not any(d["id"] == device_id for d in data.devices):
                return _error(404, "Device not found")
            return page(request, store(device_id) or [])

    for kind in ("physicalinterfaces", "subinterfaces", "etherchannelinterfaces", "vlaninterfaces"):
        per_device(f"/{kind}", partial(_interfaces_of, data, kind))
    per_device("/routing/ipv4staticroutes", lambda dev: data.static_routes.get(dev, []))
    per_device("/routing/bgpgeneralsettings", lambda dev: data.bgp_general.get(dev, []))
    per_device("/routing/bgp", lambda dev: data.bgp.get(dev, []))
    return router
