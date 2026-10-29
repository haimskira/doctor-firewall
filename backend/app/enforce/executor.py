"""Phase 5: apply one approved batch to the FMC, verify, deploy — or roll back.

This module is the only code that changes FMC configuration. Guarantees:

* It runs only for a batch in status ``approved`` (approved by someone other than the
  changeset's author), never more operations than the batch's deploy limit, and only while
  holding the cross-worker write lock of that FMC connection (one writer per FMC).
* Before every write it re-reads the object and compares it with the plan's ``expect``
  (name, field / member identities). Any difference — someone changed it since the snapshot —
  stops the batch before that write ("drift").
* Every write's undo step is journaled in the database *before* the write is sent. If a
  write, the verification or the deploy fails, the journal is undone in reverse order (ids
  of re-created objects are mapped), and the batch ends ``rolled_back`` — or ``failed`` if
  even the undo could not be completed (FMC unreachable), reported loudly; the journal
  stays, and :func:`resume_rollback` finishes it later.
* A write whose answer was lost (the connection dropped after sending) may or may not have
  landed. Every undo step is therefore idempotent: restoring a pre-image is a PUT, a create
  is undone by finding the object by name (none found: it never landed), and a deleted
  object is re-created only if nothing with its name exists.
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
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.chain import AuditEvent, AuditLog
from app.core.config import Settings
from app.core.crypto import SecretBox
from app.core.logging import scrub_text
from app.enforce.batch_proof import batch_plans, model_before
from app.enforce.plan import identity, item_ops
from app.enforce.proof import SPACE_FIELDS, Model, RuleModel, apply_plan, compare
from app.enforce.watch import open_watch
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
from app.workers import progress

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
# The variable set an intrusion policy uses when a rule has none (built into every FMC).
DEFAULT_VARIABLE_SET = "Default-Set"
READ_ONLY_KEYS = ("id", "links", "metadata")
DEPLOYED = frozenset({"deployed", "success", "succeeded", "completed"})
ROLLBACK_ROUNDS = 3  # passes over the journal before a rollback is reported as incomplete
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


def _placement(meta: Any) -> dict[str, str | int]:
    """Where a rule goes: its category, else its section (the FMC refuses both together)."""
    if not isinstance(meta, dict):
        return {}
    if meta.get("category") and meta["category"] != "--Undefined--":
        return {"category": str(meta["category"])}
    if meta.get("section"):
        return {"section": str(meta["section"]).lower()}
    return {}


def _what(op: dict[str, Any]) -> str:
    """The rule or object an operation reads, by name (for operators, not API paths)."""
    found = op.get("expect")
    expect: dict[str, Any] = found if isinstance(found, dict) else {}
    if "rule" in op or "copy_from" in op:
        return f"rule {op.get('rule_name') or expect.get('name') or ''}".strip()
    return f"object {op.get('object_name') or expect.get('name') or ''}".strip()


class _Created(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    type: str
    name: str


def _created(made: Any, what: str) -> _Created:
    try:
        return _Created.model_validate(made)
    except ValidationError as exc:
        raise BatchError("unexpected_response", what) from exc


# ------------------------------------------------------------------ the writer


@dataclass
class Writer:
    fmc: FmcSession
    adapter: FmcAdapter
    domain: str
    temps: dict[str, dict[str, Any]] = field(default_factory=dict)
    undo: list[dict[str, Any]] = field(default_factory=list)  # the journal
    results: list[dict[str, Any]] = field(default_factory=list)
    checks: list[Callable[[], Awaitable[None]]] = field(default_factory=list)
    persist: Callable[[list[dict[str, Any]]], None] | None = None
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    seen: dict[str, dict[str, Any]] = field(default_factory=dict)  # path -> last read
    _op: dict[str, Any] = field(default_factory=dict)  # the operation being written
    _variable_set: dict[str, Any] | None = None

    def save(self) -> None:
        if self.persist is not None:
            self.persist(copy.deepcopy(self.undo))

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

    async def get(self, path: str, what: str | None = None) -> dict[str, Any]:
        item = await self.fmc.get_json(path, allow_not_found=True)
        if item is None:
            raise BatchError("drift", f"{what or path} no longer exists in the FMC")
        if not isinstance(item, dict):
            raise BatchError("unexpected_response", path)
        self.seen[path] = item
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
            "set_inspection": self.set_inspection,
        }.get(str(op.get("op")))
        if handler is None:
            raise BatchError("unsupported_operation", str(op.get("op")))
        self._op = op
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

    async def journaled(
        self,
        step: dict[str, Any],
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
        applied: Callable[[Any], None] | None = None,
    ) -> Any:
        """A write whose undo ``step`` is saved first; ``applied`` completes it afterwards.

        Refused by the FMC (4xx): nothing changed, the step is dropped. Any other failure
        (connection lost, 5xx) leaves the step as ``intent`` — the write may have landed.
        """
        step["state"] = "intent"
        step.setdefault("op", str(self._op.get("op", "")))
        step.setdefault(
            "label",
            str(
                self._op.get("rule_name")
                or self._op.get("object_name")
                or self._op.get("name")
                or ""
            ),
        )
        self.undo.append(step)
        self.save()
        try:
            made = await self.write(method, path, body, params)
        except BatchError:
            self.undo.remove(step)
            self.save()
            raise
        if applied is not None:
            applied(made)
        step["state"] = "applied"
        self.save()
        return made

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
        step: dict[str, Any] = {
            "undo": "delete",
            "find": {"path": self.object_path(op["type"]), "name": op["name"]},
        }

        def applied(made: Any) -> None:
            created = _created(made, "object create")
            step["path"] = self.object_path(created.type, created.id)

        made = await self.journaled(
            step, "POST", self.object_path(op["type"]), body, applied=applied
        )
        created = _created(made, "object create")
        self.temps[op["temp"]] = {"id": created.id, "type": created.type, "name": created.name}
        self.results.append({"op": "create_object", "name": created.name, "id": created.id})

        async def verify() -> None:
            await self.get(self.object_path(created.type, created.id))

        self.checks.append(verify)

    async def update_group(self, op: dict[str, Any]) -> None:
        path = self.object_path(op["type"], op["object"])
        item = await self.get(path, _what(op))
        record = self.adapter.map_object(OBJECT_RESOURCES[op["type"]], item)
        if item.get("name") != op["expect"]["name"] or sorted(
            _record_identity(m) for m in record.members
        ) != sorted(op["expect"]["members"]):
            raise BatchError("drift", f"group {op.get('object_name')} changed in the FMC")
        body = {k: v for k, v in copy.deepcopy(item).items() if k not in ("links", "metadata")}
        body.pop("objects", None)
        body.pop("literals", None)
        body.update(_field_json(op["members"], self.temps) or {})
        await self.journaled(
            {"undo": "restore", "path": path, "body": self._clean(item, keep_id=True)},
            "PUT",
            path,
            body,
        )
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
        item = await self.get(path, _what(op))
        if item.get("name") != op["expect"]["name"]:
            raise BatchError("drift", f"object {op.get('object_name')} was renamed in the FMC")
        body = self._clean(item, keep_id=True)
        body["name"] = op["name"]
        await self.journaled(
            {"undo": "restore", "path": path, "body": self._clean(item, keep_id=True)},
            "PUT",
            path,
            body,
        )
        self.results.append({"op": "rename_object", "name": op["name"], "id": op["object"]})

        async def verify() -> None:
            if (await self.get(path)).get("name") != op["name"]:
                raise BatchError("verification_failed", f"rename of {op.get('object_name')}")

        self.checks.append(verify)

    async def delete_object(self, op: dict[str, Any]) -> None:
        path = self.object_path(op["type"], op["object"])
        item = await self.get(path, _what(op))
        if item.get("name") != op["expect"]["name"]:
            raise BatchError("drift", f"object {op.get('object_name')} was renamed in the FMC")
        await self.journaled(
            {
                "undo": "recreate",
                "path": self.object_path(op["type"]),
                "body": self._clean(item),
                "name": item["name"],
                "recreates": op["object"],
            },
            "DELETE",
            path,
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
        item = await self.get(path, _what(op))
        self.check_rule(op, item, op["expect"])
        body = self._clean(item, keep_id=True)
        self.apply_fields(body, op.get("set", {}))
        if "name" in op:
            body["name"] = op["name"]
        await self.journaled(
            {"undo": "restore", "path": path, "body": self._clean(item, keep_id=True)},
            "PUT",
            path,
            body,
        )
        self.results.append({"op": "update_rule", "name": body["name"], "id": op["rule"]})
        await self._expect_rule(op, path, body["name"])

    async def create_rule(self, op: dict[str, Any]) -> None:
        source_path = self.rule_path(op, op["copy_from"])
        source = await self.get(source_path, _what(op))
        self.check_rule(op, source, op["expect"])
        anchor = await self.get(self.rule_path(op, op["insert_after"]))
        index = (anchor.get("metadata") or {}).get("ruleIndex")
        if not isinstance(index, int):
            raise BatchError("unexpected_response", "rule without ruleIndex")
        params: dict[str, str | int] = {"insertAfter": index, **_placement(source.get("metadata"))}
        body = self._clean(source)
        body["name"] = op["name"]
        self.apply_fields(body, op.get("set", {}))
        step: dict[str, Any] = {
            "undo": "delete",
            "find": {"path": self.rule_base(op), "name": op["name"]},
        }

        def applied(made: Any) -> None:
            step["path"] = f"{self.rule_base(op)}/{_created(made, 'rule create').id}"

        made = await self.journaled(step, "POST", self.rule_base(op), body, params, applied)
        created = _created(made, "rule create")
        self.temps[op["temp"]] = {"id": created.id, "type": created.type, "name": created.name}
        path = f"{self.rule_base(op)}/{created.id}"
        self.results.append({"op": "create_rule", "name": created.name, "id": created.id})
        await self._expect_rule(op, path, op["name"])

    async def delete_rule(self, op: dict[str, Any]) -> None:
        path = self.rule_path(op, op["rule"])
        item = await self.get(path, _what(op))
        if item.get("name") != op["expect"]["name"]:
            raise BatchError("drift", f"rule {op.get('rule_name')} was renamed in the FMC")
        meta = item.get("metadata") or {}
        params: dict[str, str | int] = {}
        if isinstance(meta.get("ruleIndex"), int):
            params["insertBefore"] = int(meta["ruleIndex"])
        params.update(_placement(meta))
        await self.journaled(
            {
                "undo": "recreate",
                "path": self.rule_base(op),
                "body": self._clean(item),
                "params": params,
                "name": item["name"],
                "recreates": op["rule"],
            },
            "DELETE",
            path,
        )
        self.results.append({"op": "delete_rule", "name": op.get("rule_name"), "id": op["rule"]})

        async def verify() -> None:
            if await self.fmc.get_json(path, allow_not_found=True) is not None:
                raise BatchError("verification_failed", f"rule {op.get('rule_name')} still exists")

        self.checks.append(verify)

    async def default_variable_set(self) -> dict[str, Any]:
        """The FMC's built-in variable set (read once per batch)."""
        if self._variable_set is None:
            listing = await self.fmc.get_json(
                self.path("/object/variablesets"), {"limit": 1000, "offset": 0}
            )
            items = listing.get("items", []) if isinstance(listing, dict) else []
            found = next(
                (
                    i
                    for i in items
                    if isinstance(i, dict)
                    and i.get("name") == DEFAULT_VARIABLE_SET
                    and isinstance(i.get("id"), str)
                ),
                None,
            )
            if found is None:
                raise BatchError("variable_set_missing", DEFAULT_VARIABLE_SET)
            self._variable_set = {
                "id": found["id"],
                "name": DEFAULT_VARIABLE_SET,
                "type": "VariableSet",
            }
        return self._variable_set

    async def set_inspection(self, op: dict[str, Any]) -> None:
        if op.get("policy_kind") != "access":
            raise BatchError("unsupported_rule_kind", str(op.get("policy_kind")))
        path = self.rule_path(op, op["rule"])
        item = await self.get(path, _what(op))
        expect = op["expect"]

        def ref_id(value: Any) -> str | None:
            return str(value["id"]) if isinstance(value, dict) and "id" in value else None

        if item.get("name") != expect["name"]:
            raise BatchError("drift", f"rule {op.get('rule_name')} was renamed in the FMC")
        if (
            item.get("action") != expect["action"]
            or ref_id(item.get("ipsPolicy")) != expect.get("ips")
            or ref_id(item.get("filePolicy")) != expect.get("file")
        ):
            raise BatchError(
                "drift", f"rule {op.get('rule_name')}: action or inspection changed in the FMC"
            )
        body = self._clean(item, keep_id=True)
        if "action" in op:
            body["action"] = op["action"]
        if "ips" in op:
            body["ipsPolicy"] = dict(op["ips"])
            if ref_id(body.get("variableSet")) is None:
                body["variableSet"] = dict(await self.default_variable_set())
        if "file" in op:
            body["filePolicy"] = dict(op["file"])
        await self.journaled(
            {"undo": "restore", "path": path, "body": self._clean(item, keep_id=True)},
            "PUT",
            path,
            body,
        )
        self.results.append({"op": "set_inspection", "name": body["name"], "id": op["rule"]})
        wanted = (
            body["action"],
            ref_id(body.get("ipsPolicy")),
            ref_id(body.get("filePolicy")),
        )

        async def verify() -> None:
            after = await self.get(path)
            found = (
                after.get("action"),
                ref_id(after.get("ipsPolicy")),
                ref_id(after.get("filePolicy")),
            )
            if found != wanted:
                raise BatchError("verification_failed", f"inspection of {op.get('rule_name')}")

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
        for n, check in enumerate(self.checks):
            progress.advance(n, len(self.checks))
            await check()

    def _read_back(self, path: str, what: str) -> dict[str, Any]:
        item = self.seen.get(path)
        if item is None:
            raise BatchError("proof_unreadable", what)
        return item

    def _rule_model(self, op: dict[str, Any], item: dict[str, Any]) -> RuleModel:
        rec = self.adapter.map_any_rule(RULE_KINDS[str(op["policy_kind"])], None, item, 1)
        refs: dict[str, list[tuple[str | None, str | None, str | None]]] = {}
        for fld, ref in rec.refs:
            if fld.value in SPACE_FIELDS:
                refs.setdefault(fld.value, []).append(
                    (ref.object_id, ref.literal, ref.literal_kind)
                )
        return RuleModel(
            key=rec.fmc_id,
            name=rec.name,
            enabled=rec.enabled,
            action=rec.action.upper(),
            ips=rec.ips_policy_id,
            file=rec.file_policy_id,
            refs=refs,
        )

    def actual_model(self, before: Model, ops: list[dict[str, Any]]) -> Model:
        """The rulebase as the FMC holds it after this batch: ``before`` with every touched
        rule and object replaced by what verification read back."""
        after = before.clone()
        for op in ops:
            kind = op.get("op")
            if kind in ("create_object", "update_group"):
                if kind == "create_object":
                    made = self.temps[str(op["temp"])]
                    oid, otype = str(made["id"]), str(made["type"])
                else:
                    oid, otype = str(op["object"]), str(op["type"])
                rec = self.adapter.map_object(
                    OBJECT_RESOURCES[otype],
                    self._read_back(
                        self.object_path(otype, oid),
                        f"object {op.get('name') or op.get('object_name')}",
                    ),
                )
                if rec.members or rec.kind.value.endswith("group"):
                    after.objects[oid] = (rec.kind.value, None)
                    after.members[oid] = [
                        (m.object_id, m.literal, m.literal_kind) for m in rec.members
                    ]
                else:
                    after.objects[oid] = (rec.kind.value, rec.value)
            elif kind == "delete_object":
                after.objects.pop(str(op["object"]), None)
                after.members.pop(str(op["object"]), None)
            elif kind in ("create_rule", "update_rule", "set_inspection", "delete_rule"):
                policy = after.policies.get(str(op.get("policy")))
                if policy is None:
                    continue
                rules = policy.rules
                if kind == "create_rule":
                    rid = str(self.temps[str(op["temp"])]["id"])
                    model = self._rule_model(
                        op, self._read_back(f"{self.rule_base(op)}/{rid}", f"rule {op['name']}")
                    )
                    anchor = str(op["insert_after"])
                    if anchor in self.temps:
                        anchor = str(self.temps[anchor]["id"])
                    at = next(i for i, r in enumerate(rules) if r.key == anchor)
                    rules.insert(at + 1, model)
                    continue
                at = next(i for i, r in enumerate(rules) if r.key == str(op["rule"]))
                if kind == "delete_rule":
                    rules.pop(at)
                else:
                    rules[at] = self._rule_model(
                        op, self._read_back(self.rule_path(op, op["rule"]), _what(op))
                    )
        return after

    def record_after(self) -> None:
        """Keep, per journal step, what the FMC holds after the batch (read back by the
        verification): the history shows before / after, and a revert checks nothing changed
        since."""
        for step in self.undo:
            if step.get("state") != "applied":
                continue
            if step.get("undo") == "recreate":
                step["after"] = None  # deleted by the batch
                continue
            item = self.seen.get(str(step.get("path") or ""))
            step["after"] = self._clean(item, keep_id=True) if item is not None else None
        self.save()

    async def rollback(self, rounds: int = 1, wait: float = 0.0) -> list[str]:
        """Undo the journal in reverse order; returns the steps that could not be undone.

        A step that fails is skipped and the pass continues; up to ``rounds`` passes are made
        (``wait`` seconds apart) so a short outage of the FMC does not leave a half-undone
        batch. Each finished step is saved as ``undone``, so a later resume skips it.
        """
        failed: list[str] = []
        for attempt in range(rounds):
            if attempt:
                await self.sleep(wait)
            failed = []
            for done, step in enumerate(reversed(self.undo)):
                progress.advance(done, len(self.undo))
                if step.get("state") == "undone":
                    continue
                remap = {
                    str(s["recreates"]): str(s["recreated_as"])
                    for s in self.undo
                    if s.get("recreated_as") and s.get("recreates")
                }
                try:
                    await self._undo(step, remap)
                except (BatchError, FmcError) as exc:
                    what = step.get("name") or step.get("path") or step.get("find", {}).get("name")
                    failed.append(f"{step.get('undo')} {what}: {scrub_text(str(exc))[:120]}")
                    continue
                step["state"] = "undone"
                self.save()
            if not failed:
                break
        return failed

    async def _undo(self, step: dict[str, Any], remap: dict[str, str]) -> None:
        kind = step.get("undo")
        path = str(step.get("path") or "")
        for old, new in remap.items():
            path = path.replace(f"/{old}", f"/{new}")
        if kind == "restore":
            body = _replace_ids(step["body"], remap)
            # The FMC wants the id in a PUT body (journals written before it was kept lack it).
            body.setdefault("id", path.rstrip("/").rsplit("/", 1)[-1])
            await self.fmc.write_json("PUT", path, body)
        elif kind == "delete":
            if not path:  # the create's answer was lost: did it land?
                find = step["find"]
                found = await self._find(str(find["path"]), str(find["name"]))
                if found is None:
                    return
                path = f"{find['path']}/{found}"
            try:
                await self.fmc.write_json("DELETE", path)
            except FmcWriteRejectedError as exc:
                if exc.status != 404:  # already gone is what we want
                    raise
        elif kind == "recreate":
            existing = await self._find(path, str(step["name"]))
            if existing is None:
                body = _replace_ids(step["body"], remap)
                made = await self.fmc.write_json("POST", path, body, step.get("params"))
                existing = _created(made, "re-create").id
            step["recreated_as"] = existing
        else:
            raise BatchError("unknown_undo_step", str(kind))

    async def _find(self, collection: str, name: str) -> str | None:
        """Id of the item named ``name`` in an FMC collection (names are unique there)."""
        async for _offset, items in self.fmc.iter_pages(collection, params={"expanded": "false"}):
            for item in items:
                if item.get("name") == name and isinstance(item.get("id"), str):
                    return str(item["id"])
        return None


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
    started = time.monotonic()
    deadline = started + timeout_seconds
    while True:
        status_body = await fmc.get_json(
            adapter.config_path(domain, f"/job/taskstatuses/{task_id}")
        )
        state = str((status_body or {}).get("status", "")).lower()
        elapsed = int(time.monotonic() - started)
        # A deployment on FTDv takes about a minute: creep towards the end, never reach it.
        progress.advance(min(elapsed, 170), 180, state=state[:24], seconds=elapsed)
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
    seq: int
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
        connection, targets = _connection_and_targets(db, cs, b)
        items = list(
            db.scalars(
                select(ChangesetItem)
                .where(ChangesetItem.changeset_id == cs.id, ChangesetItem.batch_seq == b.seq)
                .order_by(ChangesetItem.position)
            )
        )
        ops = [op for item in items for op in item_ops(item.plan, item.position)]
        if len(ops) != b.op_count:
            raise BatchError("batch_inconsistent", f"{len(ops)} != {b.op_count}")
        b.status, b.started_at, b.error, b.journal = "running", datetime.now(UTC), None, []
        cs.status = "in_progress"
        return _Plan(
            batch_id=b.id,
            seq=b.seq,
            changeset_id=cs.id,
            title=cs.title,
            ticket=cs.ticket_id,
            approved_by=b.approved_by,
            connection=connection,
            ops=ops,
            targets=targets,
        )


def _prove_written(sessions: sessionmaker[Session], plan: _Plan, writer: Writer) -> None:
    """Compare the rulebase before the batch with what the FMC holds now (read back).

    A batch that preserves traffic must change no flow; one that changes traffic by design must
    hold exactly what its plan proved. Otherwise the batch stops here — before any deployment —
    and is rolled back.
    """
    try:
        with sessions() as db:
            before = model_before(db, plan.changeset_id, plan.seq)
            _ops, behaviors = batch_plans(db, plan.changeset_id)
        actual = writer.actual_model(before, plan.ops)
        report = compare(before, actual)
    except BatchError:
        raise
    except Exception as exc:  # no proof, no deployment: roll back
        log.exception("traffic proof could not run", extra={"batch": plan.batch_id})
        raise BatchError("proof_error", type(exc).__name__) from exc
    behaviour = behaviors.get(plan.seq, "preserves")
    report["behavior"] = behaviour
    if behaviour == "changes":
        matches = compare(apply_plan(before, plan.ops), actual)
        report["matches_plan"] = matches["ok"]
        ok = bool(matches["ok"])
    else:
        ok = bool(report["ok"])
    report["computed_at"] = datetime.now(UTC).isoformat()
    with sessions.begin() as db:
        batch = db.get(Batch, plan.batch_id, with_for_update=True)
        if batch is not None:
            batch.proof_after = report
    if not ok:
        raise BatchError(
            "proof_failed",
            f"{report['differences']} flows would change"
            if behaviour == "preserves"
            else "the FMC does not hold what the plan proved",
        )


def _connection_and_targets(
    db: Session, cs: Changeset, b: Batch
) -> tuple[tuple[str, int, str, str, str], set[str]]:
    conn = db.get(FmcConnection, cs.connection_id) if cs.connection_id else None
    if conn is None:
        raise BatchError("connection_deleted")
    targets = set(b.clusters)
    if cs.snapshot_id is not None:
        for c in db.scalars(
            select(Cluster).where(
                Cluster.snapshot_id == cs.snapshot_id, Cluster.fmc_id.in_(b.clusters)
            )
        ):
            targets |= {str(m.get("id")) for m in c.members if m.get("id")}
    connection = (
        conn.host,
        conn.port,
        conn.username,
        conn.password_enc,
        FmcConnection.password_context(conn.id),
    )
    return connection, targets


def _journal_sink(
    sessions: sessionmaker[Session], batch_id: int
) -> Callable[[list[dict[str, Any]]], None]:
    """Persist the undo journal of a batch (its own short transaction, before each write)."""

    def save(journal: list[dict[str, Any]]) -> None:
        with sessions.begin() as db:
            b = db.get(Batch, batch_id, with_for_update=True)
            if b is not None:
                b.journal = journal

    return save


def _unclaim(sessions: sessionmaker[Session], plan: _Plan, error: str | None = None) -> None:
    """Nothing was written: the batch goes back to approved (``error``: why it did not run)."""
    with sessions.begin() as db:
        b = db.get(Batch, plan.batch_id, with_for_update=True)
        if b is not None and b.status == "running":
            b.status, b.started_at, b.error = "approved", None, error


def _finish(
    sessions: sessionmaker[Session],
    audit: AuditLog,
    plan: _Plan,
    status: str,
    *,
    error: str | None,
    results: list[dict[str, Any]],
    task_id: str | None,
    settings: Settings | None = None,
) -> None:
    with sessions.begin() as db:
        b = db.get(Batch, plan.batch_id, with_for_update=True)
        cs = db.get(Changeset, plan.changeset_id, with_for_update=True)
        if b is None or cs is None:
            return
        b.status, b.error, b.results = status, error, results
        b.finished_at, b.deploy_job_id = datetime.now(UTC), task_id
        if status == "deployed":
            if settings is not None:
                open_watch(db, b, settings, b.finished_at)
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
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
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
                requests_per_minute=settings.fmc_requests_per_minute,
                concurrency=1,
                connect_retries=settings.fmc_connect_retries,
            ),
        ) as fmc:
            adapter = select_adapter(await server_version(fmc))
            writer = Writer(
                fmc=fmc,
                adapter=adapter,
                domain=fmc.domain_uuid,
                persist=_journal_sink(sessions, plan.batch_id),
                sleep=sleep,
            )
            try:
                progress.phase("batch_write", 2, 60)
                for n, op in enumerate(plan.ops):
                    progress.advance(n, len(plan.ops))
                    await writer.run(op)
                progress.phase("batch_verify", 60, 63)
                await writer.verify()
                progress.phase("proof_after", 63, 66)
                _prove_written(sessions, plan, writer)
                writer.record_after()
                progress.phase("deploying", 66, 98)
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
                # A BatchError's text already starts with its code: keep the detail only.
                detail = scrub_text(exc.detail if isinstance(exc, BatchError) else str(exc))[:300]
                log.error(
                    "batch failed, rolling back",
                    extra={"batch": batch_id, "code": code, "detail": detail},
                )
                progress.phase("rolling_back", 66, 85)
                left = await writer.rollback(ROLLBACK_ROUNDS, settings.rollback_retry_seconds)
                if writer.undo and not left:
                    progress.phase("deploying", 85, 98)
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
        # Could not even open the session / read the version: nothing was written, so the
        # batch stays approved and can simply run again (the reason is kept for the operator).
        reason = f"{exc.code}: {scrub_text(str(exc))[:200]}"
        log.warning("batch did not start", extra={"batch": plan.batch_id, "reason": reason})
        _unclaim(sessions, plan, reason)
        audit_db_event = AuditEvent(
            actor="system:enforcer",
            actor_id=None,
            action="changeset.batch_not_started",
            outcome="failure",
            target=plan.title[:256],
            details={"changeset_id": plan.changeset_id, "batch_id": plan.batch_id, "error": reason},
        )
        with sessions.begin() as db:
            audit.record(db, audit_db_event)
        return {"ok": False, "error": exc.code, "status": "approved", "detail": reason}
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
        settings=settings,
    )
    return {
        "ok": True,
        "status": "deployed",
        "operations": len(writer.results),
        "task": task_id,
    }


def rollback_resumable(b: Batch, now: datetime, stale_after: timedelta) -> bool:
    """A failed batch with undo left to do (journal steps, or the re-deploy after them), or
    one whose worker died mid-run."""
    if b.status == "failed":
        return bool(b.journal) and (
            any(step.get("state") != "undone" for step in b.journal)
            or any(r.get("op") == "undo_failed" for r in b.results)
        )
    return (
        b.status == "running"
        and b.started_at is not None
        and now - b.started_at > stale_after
        and bool(b.journal)
    )


async def resume_rollback(
    batch_id: int,
    *,
    sessions: sessionmaker[Session],
    box: SecretBox,
    audit: AuditLog,
    settings: Settings,
    lock: Callable[[str, int], Awaitable[Callable[[], Awaitable[None]] | None]],
    transport: Any = None,
    poll_seconds: float | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict[str, Any]:
    """Finish the rollback of a batch from its saved journal, then re-deploy the devices.

    Every undo step is idempotent, so steps that already took effect (or writes that never
    landed) are harmless. The batch ends ``rolled_back``, or stays ``failed`` with what is
    still left.
    """
    with sessions.begin() as db:
        b = db.get(Batch, batch_id, with_for_update=True)
        cs = db.get(Changeset, b.changeset_id) if b is not None else None
        if b is None or cs is None:
            raise BatchError("not_found")
        if not rollback_resumable(b, datetime.now(UTC), stale_after_run(settings)):
            raise BatchError("nothing_to_undo")
        connection, targets = _connection_and_targets(db, cs, b)
        journal = copy.deepcopy(b.journal)
        previous = (b.status, b.error)
        results = [r for r in b.results if r.get("op") != "undo_failed"]
        b.status = "running"
        plan = _Plan(
            batch_id=b.id,
            seq=b.seq,
            changeset_id=cs.id,
            title=cs.title,
            ticket=cs.ticket_id,
            approved_by=b.approved_by or "",
            connection=connection,
            ops=[],
            targets=targets,
        )

    def put_back(reason: str) -> dict[str, Any]:
        with sessions.begin() as db:
            b = db.get(Batch, batch_id, with_for_update=True)
            if b is not None:
                b.status = "failed"
                b.error = f"{previous[1] or ''} | resume: {reason}"[:500]
        return {"ok": False, "error": reason, "status": "failed"}

    host, port, username, token, context = connection
    release = await lock(f"df:fmc-write:{host}:{port}", settings.write_lock_ttl_seconds)
    if release is None:
        return put_back("write_lock_busy")

    def password_provider() -> bytearray:
        return box.decrypt(token, context)

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
                requests_per_minute=settings.fmc_requests_per_minute,
                concurrency=1,
                connect_retries=settings.fmc_connect_retries,
            ),
        ) as fmc:
            adapter = select_adapter(await server_version(fmc))
            writer = Writer(
                fmc=fmc,
                adapter=adapter,
                domain=fmc.domain_uuid,
                undo=journal,
                persist=_journal_sink(sessions, batch_id),
                sleep=sleep,
            )
            progress.phase("rolling_back", 2, 60)
            left = await writer.rollback(ROLLBACK_ROUNDS, settings.rollback_retry_seconds)
            if not left:
                progress.phase("deploying", 60, 98)
                try:
                    await deploy(
                        fmc,
                        adapter,
                        fmc.domain_uuid,
                        targets,
                        poll_seconds=settings.deploy_poll_seconds
                        if poll_seconds is None
                        else poll_seconds,
                        timeout_seconds=settings.deploy_timeout_seconds,
                    )
                except (BatchError, FmcError) as again:
                    left.append(f"redeploy after rollback: {scrub_text(str(again))[:120]}")
    except FmcError as exc:
        return put_back(f"{exc.code}: {scrub_text(str(exc))[:200]}")
    finally:
        await release()
    status = "rolled_back" if not left else "failed"
    _finish(
        sessions,
        audit,
        plan,
        status,
        error=previous[1] if not left else f"{previous[1] or ''} | resume: incomplete"[:500],
        results=[*results, *({"op": "undo_failed", "detail": x} for x in left)],
        task_id=None,
    )
    return {"ok": not left, "status": status, "undo_failed": left}


def stale_after_run(settings: Settings) -> timedelta:
    """A batch still ``running`` after this long has lost its worker (the job timed out)."""
    return timedelta(seconds=settings.deploy_timeout_seconds + 3600)


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
