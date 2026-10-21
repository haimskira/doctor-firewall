"""Phase 5: apply one approved batch to the FMC, verify, deploy — or roll back.

This module is the only code that changes FMC configuration. Guarantees:

* It runs only for a batch in status ``approved`` (approved by someone other than the
  changeset's author), never more operations than the batch's deploy limit, and only while
  holding the cross-worker write lock of that FMC connection (one writer per FMC).
* Before every write it re-reads the object and compares it with the plan's ``expect``
  (name, field / member identities). Any difference — someone changed it since the snapshot —
  stops the batch before that write ("drift").
* Every write is logged with what is needed to undo it. If a write, the verification or the
  deploy fails, the writes already made are undone in reverse order (ids of re-created
  objects are mapped), and the batch ends ``rolled_back`` (or ``failed`` if even the undo
  could not be completed — reported loudly, with the remaining steps).
* After the writes, every touched object is re-read and checked against the intended state;
  then the affected devices are deployed and the deployment task is polled to completion.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.chain import AuditEvent, AuditLog
from app.core.config import Settings
from app.core.crypto import SecretBox
from app.core.logging import scrub_text
from app.enforce.plan import identity
from app.fmc.adapters import FmcAdapter, select_adapter
from app.fmc.client import FmcSession, ThrottlePolicy, build_ssl_context
from app.fmc.errors import FmcError, FmcWriteRejectedError
from app.fmc.probe import server_version
from app.fmc.records import PolicyKind
from app.fmc.records import Ref as RecordRef
from app.models.assets import ClusterSetting
from app.models.enforce import Batch, Changeset, ChangesetItem
from app.models.fmc import FmcConnection
from app.models.inventory import Cluster

log = logging.getLogger(__name__)

FIELD_KEYS = {
    "src_zone": "sourceZones",
    "dst_zone": "destinationZones",
    "src_net": "sourceNetworks",
    "dst_net": "destinationNetworks",
    "src_port": "sourcePorts",
    "dst_port": "destinationPorts",
    "url": "urls",
    "src_sgt": "sourceSecurityGroupTags",
    "dst_sgt": "destinationSecurityGroupTags",
    "src_dyn": "sourceDynamicObjects",
    "dst_dyn": "destinationDynamicObjects",
    "user": "users",
    "vlan": "vlanTags",
}
RULE_BASES = {
    "access": "/policy/accesspolicies/{policy}/accessrules",
    "prefilter": "/policy/prefilterpolicies/{policy}/prefilterrules",
}
RULE_KINDS = {"access": PolicyKind.ACCESS, "prefilter": PolicyKind.PREFILTER}
OBJECT_RESOURCES = {
    "Host": "hosts",
    "Network": "networks",
    "Range": "ranges",
    "FQDN": "fqdns",
    "ProtocolPortObject": "protocolportobjects",
    "NetworkGroup": "networkgroups",
    "PortObjectGroup": "portobjectgroups",
    "ICMPV4Object": "icmpv4objects",
    "ICMPV6Object": "icmpv6objects",
    "SecurityZone": "securityzones",
    "Url": "urls",
    "UrlGroup": "urlgroups",
    "DynamicObject": "dynamicobjects",
}
PROTOCOL_NUMBERS = {"TCP": "6", "UDP": "17", "SCTP": "132"}
READ_ONLY_KEYS = ("id", "links", "metadata")
DEPLOYED = frozenset({"deployed", "success", "succeeded", "completed"})
DEPLOY_FAILED = frozenset({"failed", "error", "aborted", "cancelled"})


class BatchError(Exception):
    """The batch cannot proceed. ``code`` is shown to operators; ``detail`` is for the log."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------ JSON helpers


def _literal_json(ref: dict[str, Any]) -> dict[str, Any]:
    value = str(ref.get("literal") or "")
    kind = ref.get("literal_kind")
    if kind == "range":
        return {"type": "Range", "value": value}
    if kind == "address":
        if value.endswith(("/32", "/128")):
            return {"type": "Host", "value": value.rsplit("/", 1)[0]}
        return {"type": "Network", "value": value}
    if kind == "port":
        proto, _, port = value.partition("/")
        number = PROTOCOL_NUMBERS.get(proto)
        if number is None or not port or port == "any":
            raise BatchError("unsupported_literal", value)
        return {"type": "PortLiteral", "protocol": number, "port": port}
    raise BatchError("unsupported_literal", f"{kind}:{value}")


def _resolve(ref: dict[str, Any], temps: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if "temp" in ref:
        made = temps.get(str(ref["temp"]))
        if made is None:
            raise BatchError("unresolved_reference", str(ref["temp"]))
        return made
    return ref


def _field_json(
    refs: list[dict[str, Any]], temps: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    objects: list[dict[str, Any]] = []
    literals: list[dict[str, Any]] = []
    for ref in refs:
        if "literal" in ref:
            literals.append(_literal_json(ref))
            continue
        target = _resolve(ref, temps)
        objects.append({"id": target["id"], "type": target["type"], "name": target["name"]})
    if not objects and not literals:
        return None  # empty field = any
    out: dict[str, Any] = {}
    if objects:
        out["objects"] = objects
    if literals:
        out["literals"] = literals
    return out


def _record_identity(ref: RecordRef) -> str:
    return f"o:{ref.object_id}" if ref.object_id is not None else f"l:{ref.literal}"


def _replace_ids(value: Any, mapping: dict[str, str]) -> Any:
    """Deep copy with object ids remapped (objects re-created during a rollback get new ids)."""
    if isinstance(value, dict):
        return {
            k: (mapping.get(v, v) if k == "id" and isinstance(v, str) else _replace_ids(v, mapping))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_replace_ids(v, mapping) for v in value]
    return value


class _Created(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    type: str
    name: str


# ------------------------------------------------------------------ the writer


@dataclass
class Writer:
    fmc: FmcSession
    adapter: FmcAdapter
    domain: str
    temps: dict[str, dict[str, Any]] = field(default_factory=dict)
    undo: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    checks: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    def path(self, suffix: str) -> str:
        return self.adapter.config_path(self.domain, suffix)

    def rule_base(self, op: dict[str, Any]) -> str:
        base = RULE_BASES.get(str(op.get("policy_kind")))
        if base is None:
            raise BatchError("unsupported_rule_kind", str(op.get("policy_kind")))
        return self.path(base.format(policy=op["policy"]))

    def object_path(self, fmc_type: str, object_id: str | None = None) -> str:
        resource = OBJECT_RESOURCES.get(fmc_type)
        if resource is None:
            raise BatchError("unsupported_object_type", fmc_type)
        return self.path(f"/object/{resource}" + (f"/{object_id}" if object_id else ""))

    async def get(self, path: str) -> dict[str, Any]:
        item = await self.fmc.get_json(path, allow_not_found=True)
        if item is None:
            raise BatchError("drift", f"{path} no longer exists")
        if not isinstance(item, dict):
            raise BatchError("unexpected_response", path)
        return item

    def rule_fields(self, op: dict[str, Any], item: dict[str, Any]) -> dict[str, list[str]]:
        record = self.adapter.map_any_rule(RULE_KINDS[str(op["policy_kind"])], None, item, 1)
        out: dict[str, list[str]] = {}
        for fld, ref in record.refs:
            out.setdefault(fld.value, []).append(_record_identity(ref))
        return out

    def check_rule(self, op: dict[str, Any], item: dict[str, Any], expect: dict[str, Any]) -> None:
        if item.get("name") != expect.get("name"):
            raise BatchError("drift", f"rule {op.get('rule_name')} was renamed in the FMC")
        current = self.rule_fields(op, item)
        for fld, wanted in expect.get("fields", {}).items():
            if sorted(current.get(fld, [])) != sorted(wanted):
                raise BatchError(
                    "drift", f"rule {op.get('rule_name')}: field {fld} changed in the FMC"
                )

    def apply_fields(self, body: dict[str, Any], sets: dict[str, list[dict[str, Any]]]) -> None:
        for fld, refs in sets.items():
            key = FIELD_KEYS.get(fld)
            if key is None:
                raise BatchError("unsupported_field", fld)
            value = _field_json(refs, self.temps)
            if value is None:
                body.pop(key, None)
            else:
                body[key] = value

    def rule_path(self, op: dict[str, Any], rule: str) -> str:
        if rule.startswith("new:"):
            made = self.temps.get(rule)
            if made is None:
                raise BatchError("unresolved_reference", rule)
            rule = made["id"]
        return f"{self.rule_base(op)}/{rule}"

    # ---- operations

    async def run(self, op: dict[str, Any]) -> None:
        handler = {
            "create_object": self.create_object,
            "update_group": self.update_group,
            "rename_object": self.rename_object,
            "delete_object": self.delete_object,
            "update_rule": self.update_rule,
            "create_rule": self.create_rule,
            "delete_rule": self.delete_rule,
        }.get(str(op.get("op")))
        if handler is None:
            raise BatchError("unsupported_operation", str(op.get("op")))
        await handler(op)

    async def write(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
    ) -> Any:
        try:
            return await self.fmc.write_json(method, path, body, params)
        except FmcWriteRejectedError as exc:
            raise BatchError("write_rejected", exc.description or str(exc)) from exc

    async def create_object(self, op: dict[str, Any]) -> None:
        body: dict[str, Any] = {"name": op["name"], "type": op["type"]}
        kind = op.get("kind")
        value = str(op.get("value") or "")
        if kind == "host":
            body["value"] = value.rsplit("/", 1)[0]
        elif kind in ("network", "range"):
            body["value"] = value
        elif kind == "port":
            proto, _, port = value.partition("/")
            body["protocol"], body["port"] = proto, port
        elif kind == "network_group":
            members = _field_json(op.get("members", []), self.temps) or {}
            body.update(members)
        else:
            raise BatchError("unsupported_object_kind", str(kind))
        made = await self.write("POST", self.object_path(op["type"]), body)
        try:
            created = _Created.model_validate(made)
        except ValidationError as exc:
            raise BatchError("unexpected_response", "object create") from exc
        self.temps[op["temp"]] = {"id": created.id, "type": created.type, "name": created.name}
        self.undo.append({"method": "DELETE", "path": self.object_path(created.type, created.id)})
        self.results.append({"op": "create_object", "name": created.name, "id": created.id})

        async def verify() -> None:
            await self.get(self.object_path(created.type, created.id))

        self.checks.append(verify)

    async def update_group(self, op: dict[str, Any]) -> None:
        path = self.object_path(op["type"], op["object"])
        item = await self.get(path)
        record = self.adapter.map_object(OBJECT_RESOURCES[op["type"]], item)
        if item.get("name") != op["expect"]["name"] or sorted(
            _record_identity(m) for m in record.members
        ) != sorted(op["expect"]["members"]):
            raise BatchError("drift", f"group {op.get('object_name')} changed in the FMC")
        body = {k: v for k, v in copy.deepcopy(item).items() if k not in ("links", "metadata")}
        body.pop("objects", None)
        body.pop("literals", None)
        body.update(_field_json(op["members"], self.temps) or {})
        await self.write("PUT", path, body)
        self.undo.append({"method": "PUT", "path": path, "body": self._clean(item)})
        self.results.append(
            {"op": "update_group", "name": op.get("object_name"), "id": op["object"]}
        )
        wanted = sorted(
            identity(_resolve(m, self.temps)) if "temp" in m else identity(m) for m in op["members"]
        )

        async def verify() -> None:
            after = self.adapter.map_object(OBJECT_RESOURCES[op["type"]], await self.get(path))
            if sorted(_record_identity(m) for m in after.members) != wanted:
                raise BatchError("verification_failed", f"group {op.get('object_name')}")

        self.checks.append(verify)

    async def rename_object(self, op: dict[str, Any]) -> None:
        path = self.object_path(op["type"], op["object"])
        item = await self.get(path)
        if item.get("name") != op["expect"]["name"]:
            raise BatchError("drift", f"object {op.get('object_name')} was renamed in the FMC")
        body = self._clean(item, keep_id=True)
        body["name"] = op["name"]
        await self.write("PUT", path, body)
        self.undo.append({"method": "PUT", "path": path, "body": self._clean(item, keep_id=True)})
        self.results.append({"op": "rename_object", "name": op["name"], "id": op["object"]})

        async def verify() -> None:
            if (await self.get(path)).get("name") != op["name"]:
                raise BatchError("verification_failed", f"rename of {op.get('object_name')}")

        self.checks.append(verify)

    async def delete_object(self, op: dict[str, Any]) -> None:
        path = self.object_path(op["type"], op["object"])
        item = await self.get(path)
        if item.get("name") != op["expect"]["name"]:
            raise BatchError("drift", f"object {op.get('object_name')} was renamed in the FMC")
        await self.write("DELETE", path)
        self.undo.append(
            {
                "method": "POST",
                "path": self.object_path(op["type"]),
                "body": self._clean(item),
                "recreates": op["object"],
            }
        )
        self.results.append(
            {"op": "delete_object", "name": op.get("object_name"), "id": op["object"]}
        )

        async def verify() -> None:
            if await self.fmc.get_json(path, allow_not_found=True) is not None:
                raise BatchError(
                    "verification_failed", f"object {op.get('object_name')} still exists"
                )

        self.checks.append(verify)

    async def update_rule(self, op: dict[str, Any]) -> None:
        path = self.rule_path(op, op["rule"])
        item = await self.get(path)
        self.check_rule(op, item, op["expect"])
        body = self._clean(item, keep_id=True)
        self.apply_fields(body, op.get("set", {}))
        if "name" in op:
            body["name"] = op["name"]
        await self.write("PUT", path, body)
        self.undo.append({"method": "PUT", "path": path, "body": self._clean(item, keep_id=True)})
        self.results.append({"op": "update_rule", "name": body["name"], "id": op["rule"]})
        await self._expect_rule(op, path, body["name"])

    async def create_rule(self, op: dict[str, Any]) -> None:
        source_path = self.rule_path(op, op["copy_from"])
        source = await self.get(source_path)
        self.check_rule(op, source, op["expect"])
        anchor = await self.get(self.rule_path(op, op["insert_after"]))
        index = (anchor.get("metadata") or {}).get("ruleIndex")
        if not isinstance(index, int):
            raise BatchError("unexpected_response", "rule without ruleIndex")
        meta = source.get("metadata") or {}
        params: dict[str, str | int] = {"insertAfter": index}
        if meta.get("section"):
            params["section"] = str(meta["section"]).lower()
        if meta.get("category") and meta["category"] != "--Undefined--":
            params["category"] = str(meta["category"])
        body = self._clean(source)
        body["name"] = op["name"]
        self.apply_fields(body, op.get("set", {}))
        made = await self.write("POST", self.rule_base(op), body, params)
        try:
            created = _Created.model_validate(made)
        except ValidationError as exc:
            raise BatchError("unexpected_response", "rule create") from exc
        self.temps[op["temp"]] = {"id": created.id, "type": created.type, "name": created.name}
        path = f"{self.rule_base(op)}/{created.id}"
        self.undo.append({"method": "DELETE", "path": path})
        self.results.append({"op": "create_rule", "name": created.name, "id": created.id})
        await self._expect_rule(op, path, op["name"])

    async def delete_rule(self, op: dict[str, Any]) -> None:
        path = self.rule_path(op, op["rule"])
        item = await self.get(path)
        if item.get("name") != op["expect"]["name"]:
            raise BatchError("drift", f"rule {op.get('rule_name')} was renamed in the FMC")
        meta = item.get("metadata") or {}
        await self.write("DELETE", path)
        params: dict[str, str | int] = {}
        if isinstance(meta.get("ruleIndex"), int):
            params["insertBefore"] = int(meta["ruleIndex"])
        if meta.get("section"):
            params["section"] = str(meta["section"]).lower()
        self.undo.append(
            {
                "method": "POST",
                "path": self.rule_base(op),
                "body": self._clean(item),
                "params": params,
            }
        )
        self.results.append({"op": "delete_rule", "name": op.get("rule_name"), "id": op["rule"]})

        async def verify() -> None:
            if await self.fmc.get_json(path, allow_not_found=True) is not None:
                raise BatchError("verification_failed", f"rule {op.get('rule_name')} still exists")

        self.checks.append(verify)

    async def _expect_rule(self, op: dict[str, Any], path: str, name: str) -> None:
        wanted = {
            fld: sorted(
                identity(_resolve(r, self.temps)) if "temp" in r else identity(r) for r in refs
            )
            for fld, refs in op.get("set", {}).items()
        }

        async def verify() -> None:
            item = await self.get(path)
            current = self.rule_fields(op, item)
            if item.get("name") != name or any(
                sorted(current.get(f, [])) != v for f, v in wanted.items()
            ):
                raise BatchError("verification_failed", f"rule {name}")

        self.checks.append(verify)

    @staticmethod
    def _clean(item: dict[str, Any], *, keep_id: bool = False) -> dict[str, Any]:
        body = copy.deepcopy(item)
        for key in READ_ONLY_KEYS:
            if key == "id" and keep_id:
                continue
            body.pop(key, None)
        return body

    async def verify(self) -> None:
        for check in self.checks:
            await check()

    async def rollback(self) -> list[str]:
        """Undo in reverse order; returns the steps that could not be undone."""
        remap: dict[str, str] = {}
        failed: list[str] = []
        for step in reversed(self.undo):
            body = _replace_ids(step.get("body"), remap) if step.get("body") is not None else None
            path = step["path"]
            for old, new in remap.items():
                path = path.replace(f"/{old}", f"/{new}")
            if isinstance(body, dict) and "id" in body:
                body["id"] = remap.get(body["id"], body["id"])
            try:
                made = await self.fmc.write_json(step["method"], path, body, step.get("params"))
            except FmcError as exc:
                failed.append(f"{step['method']} {path}: {scrub_text(str(exc))[:120]}")
                continue
            if step.get("recreates") and isinstance(made, dict) and isinstance(made.get("id"), str):
                remap[str(step["recreates"])] = made["id"]
        return failed


# ------------------------------------------------------------------ deploy


class _Deployable(BaseModel):
    model_config = ConfigDict(extra="ignore")
    version: str | int | None = None
    device: dict[str, Any]


class _DeployableList(BaseModel):
    model_config = ConfigDict(extra="ignore")
    items: list[_Deployable] = []


async def deploy(
    fmc: FmcSession,
    adapter: FmcAdapter,
    domain: str,
    targets: set[str],
    *,
    poll_seconds: float,
    timeout_seconds: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> str | None:
    """Deploy pending changes to the target devices / HA pairs; returns the task id."""
    raw = await fmc.get_json(
        adapter.config_path(domain, "/deployment/deployabledevices"), {"expanded": "true"}
    )
    try:
        listing = _DeployableList.model_validate(raw or {})
    except ValidationError as exc:
        raise BatchError("unexpected_response", "deployabledevices") from exc
    chosen = [d for d in listing.items if str(d.device.get("id")) in targets]
    if not chosen:
        return None
    version = max(str(d.version or "0") for d in chosen)
    response = await fmc.write_json(
        "POST",
        adapter.config_path(domain, "/deployment/deploymentrequests"),
        {
            "type": "DeploymentRequest",
            "version": version,
            "forceDeploy": False,
            "ignoreWarning": True,
            "deviceList": sorted(str(d.device["id"]) for d in chosen),
        },
    )
    task = ((response or {}).get("metadata") or {}).get("task") or {}
    task_id = task.get("id")
    if not isinstance(task_id, str):
        raise BatchError("unexpected_response", "deployment request without task id")
    deadline = time.monotonic() + timeout_seconds
    while True:
        status_body = await fmc.get_json(
            adapter.config_path(domain, f"/job/taskstatuses/{task_id}")
        )
        state = str((status_body or {}).get("status", "")).lower()
        if state in DEPLOYED:
            return task_id
        if state in DEPLOY_FAILED:
            raise BatchError("deploy_failed", str((status_body or {}).get("message", ""))[:200])
        if time.monotonic() > deadline:
            raise BatchError("deploy_timeout", task_id)
        await sleep(poll_seconds)


# ------------------------------------------------------------------ batch orchestration


@dataclass
class _Plan:
    batch_id: int
    changeset_id: int
    title: str
    ticket: str
    approved_by: str
    connection: tuple[str, int, str, str, str]
    ops: list[dict[str, Any]]
    targets: set[str]


def _load(sessions: sessionmaker[Session], batch_id: int, settings: Settings) -> _Plan:
    with sessions.begin() as db:
        b = db.get(Batch, batch_id, with_for_update=True)
        if b is None:
            raise BatchError("not_found")
        cs = db.get(Changeset, b.changeset_id, with_for_update=True)
        if cs is None or cs.status not in ("open", "in_progress"):
            raise BatchError("changeset_closed")
        if b.status != "approved" or b.approved_by is None:
            raise BatchError("batch_not_approved")
        if b.approved_by == cs.created_by:
            raise BatchError("author_cannot_approve")
        limits = {
            s.cluster_fmc_id: s.deploy_change_limit for s in db.scalars(select(ClusterSetting))
        }
        limit = min(
            (limits.get(c, settings.default_deploy_change_limit) for c in b.clusters),
            default=settings.default_deploy_change_limit,
        )
        if b.op_count > limit:
            raise BatchError("exceeds_deploy_limit", f"{b.op_count} > {limit}")
        conn = db.get(FmcConnection, cs.connection_id) if cs.connection_id else None
        if conn is None:
            raise BatchError("connection_deleted")
        items = list(
            db.scalars(
                select(ChangesetItem)
                .where(ChangesetItem.changeset_id == cs.id, ChangesetItem.batch_seq == b.seq)
                .order_by(ChangesetItem.position)
            )
        )
        ops = [op for item in items for op in item.plan.get("ops", [])]
        if len(ops) != b.op_count:
            raise BatchError("batch_inconsistent", f"{len(ops)} != {b.op_count}")
        targets = set(b.clusters)
        if cs.snapshot_id is not None:
            for c in db.scalars(
                select(Cluster).where(
                    Cluster.snapshot_id == cs.snapshot_id, Cluster.fmc_id.in_(b.clusters)
                )
            ):
                targets |= {str(m.get("id")) for m in c.members if m.get("id")}
        b.status, b.started_at, b.error = "running", datetime.now(UTC), None
        cs.status = "in_progress"
        return _Plan(
            batch_id=b.id,
            changeset_id=cs.id,
            title=cs.title,
            ticket=cs.ticket_id,
            approved_by=b.approved_by,
            connection=(
                conn.host,
                conn.port,
                conn.username,
                conn.password_enc,
                FmcConnection.password_context(conn.id),
            ),
            ops=ops,
            targets=targets,
        )


def _unclaim(sessions: sessionmaker[Session], plan: _Plan) -> None:
    with sessions.begin() as db:
        b = db.get(Batch, plan.batch_id, with_for_update=True)
        if b is not None and b.status == "running":
            b.status, b.started_at = "approved", None


def _finish(
    sessions: sessionmaker[Session],
    audit: AuditLog,
    plan: _Plan,
    status: str,
    *,
    error: str | None,
    results: list[dict[str, Any]],
    task_id: str | None,
) -> None:
    with sessions.begin() as db:
        b = db.get(Batch, plan.batch_id, with_for_update=True)
        cs = db.get(Changeset, plan.changeset_id, with_for_update=True)
        if b is None or cs is None:
            return
        b.status, b.error, b.results = status, error, results
        b.finished_at, b.deploy_job_id = datetime.now(UTC), task_id
        if status == "deployed":
            remaining = db.scalar(
                select(Batch.id)
                .where(Batch.changeset_id == cs.id, Batch.status != "deployed")
                .limit(1)
            )
            cs.status = "completed" if remaining is None else "in_progress"
        else:
            cs.status = "failed"
        audit.record(
            db,
            AuditEvent(
                actor="system:enforcer",
                actor_id=None,
                action=f"changeset.batch_{status}",
                outcome="success" if status == "deployed" else "failure",
                target=plan.title[:256],
                details={
                    "changeset_id": plan.changeset_id,
                    "batch_id": plan.batch_id,
                    "ticket_id": plan.ticket,
                    "approved_by": plan.approved_by,
                    "operations": len(results),
                    "error": error,
                    "deploy_task": task_id,
                },
            ),
        )


async def execute_batch(
    batch_id: int,
    *,
    sessions: sessionmaker[Session],
    box: SecretBox,
    audit: AuditLog,
    settings: Settings,
    lock: Callable[[str, int], Awaitable[Callable[[], Awaitable[None]] | None]],
    transport: Any = None,
    poll_seconds: float | None = None,
) -> dict[str, Any]:
    """Apply one approved batch. ``lock(key, ttl)`` returns a release callable or None if busy."""
    plan = _load(sessions, batch_id, settings)
    host, port, username, token, context = plan.connection
    release = await lock(f"df:fmc-write:{host}:{port}", settings.write_lock_ttl_seconds)
    if release is None:
        # Another batch is writing to this FMC: nothing happened, the batch stays approved.
        _unclaim(sessions, plan)
        return {"ok": False, "error": "write_lock_busy", "status": "approved"}

    def password_provider() -> bytearray:
        return box.decrypt(token, context)

    writer: Writer | None = None
    task_id: str | None = None
    try:
        async with FmcSession(
            host=host,
            port=port,
            username=username,
            password_provider=password_provider,
            ssl_context=build_ssl_context(settings.fmc_ca_bundle),
            timeout=settings.fmc_timeout_seconds,
            transport=transport,
            throttle=ThrottlePolicy(
                requests_per_minute=settings.fmc_requests_per_minute, concurrency=1
            ),
        ) as fmc:
            adapter = select_adapter(await server_version(fmc))
            writer = Writer(fmc=fmc, adapter=adapter, domain=fmc.domain_uuid)
            try:
                for op in plan.ops:
                    await writer.run(op)
                await writer.verify()
                task_id = await deploy(
                    fmc,
                    adapter,
                    fmc.domain_uuid,
                    plan.targets,
                    poll_seconds=settings.deploy_poll_seconds
                    if poll_seconds is None
                    else poll_seconds,
                    timeout_seconds=settings.deploy_timeout_seconds,
                )
            except (BatchError, FmcError) as exc:
                code = exc.code
                detail = scrub_text(str(exc))[:300]
                log.error(
                    "batch failed, rolling back",
                    extra={"batch": batch_id, "code": code, "detail": detail},
                )
                left = await writer.rollback()
                if writer.undo and not left:
                    # Restore the devices to the rolled-back configuration as well.
                    try:
                        await deploy(
                            fmc,
                            adapter,
                            fmc.domain_uuid,
                            plan.targets,
                            poll_seconds=settings.deploy_poll_seconds
                            if poll_seconds is None
                            else poll_seconds,
                            timeout_seconds=settings.deploy_timeout_seconds,
                        )
                    except (BatchError, FmcError) as again:
                        left.append(f"redeploy after rollback: {scrub_text(str(again))[:120]}")
                status = "rolled_back" if not left else "failed"
                results = [*writer.results, *({"op": "undo_failed", "detail": x} for x in left)]
                _finish(
                    sessions,
                    audit,
                    plan,
                    status,
                    error=f"{code}: {detail}"[:500],
                    results=results,
                    task_id=task_id,
                )
                return {"ok": False, "error": code, "status": status, "undo_failed": left}
    except FmcError as exc:
        # Could not even open the session / read the version: nothing was written.
        _finish(sessions, audit, plan, "failed", error=exc.code, results=[], task_id=None)
        return {"ok": False, "error": exc.code, "status": "failed"}
    finally:
        await release()
    _finish(
        sessions,
        audit,
        plan,
        "deployed",
        error=None,
        results=writer.results,
        task_id=task_id,
    )
    return {
        "ok": True,
        "status": "deployed",
        "operations": len(writer.results),
        "task": task_id,
    }


def redis_lock(redis: Any) -> Callable[[str, int], Awaitable[Callable[[], Awaitable[None]] | None]]:
    """``SET NX EX`` lock with an owner token; release only if still the owner."""

    async def acquire(key: str, ttl: int) -> Callable[[], Awaitable[None]] | None:
        owner = secrets.token_hex(16)
        if not redis.set(key, owner, nx=True, ex=ttl):
            return None

        async def release() -> None:
            if redis.get(key) in (owner, owner.encode()):
                redis.delete(key)

        return release

    return acquire
