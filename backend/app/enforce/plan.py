"""Executable plans: the FMC write operations a recommendation stands for.

A plan is a list of operations from a closed set. Each carries the state the system expects
to find in the FMC (``expect``) — the executor re-reads the object before every write and
stops on any difference (drift: someone changed it since the snapshot). References are
``{"id", "type", "name"}`` (existing objects), ``{"temp", "type", "name"}`` (objects created
earlier in the same plan) or ``{"literal", "literal_kind"}`` (inline values).

What cannot be executed safely is not guessed: the plan lists ``blocked`` reasons (e.g. an
object used by a static route, a rule kind the writer does not support) and such a
recommendation cannot enter a changeset.

Operation order inside a plan is the execution order; every recommendation's plan is applied
atomically within one batch (see :mod:`app.enforce.batching`).
"""

from __future__ import annotations

from typing import Any

OPS = frozenset(
    {
        "create_object",
        "update_group",
        "create_rule",
        "update_rule",
        "rename_object",
        "delete_rule",
        "delete_object",
        "set_inspection",
    }
)
# Rule kinds the writer supports (same field layout in the FMC API).
WRITABLE_RULE_KINDS = frozenset({"access", "prefilter"})
# FMC types the writer can create.
CREATABLE_TYPES = {
    "host": "Host",
    "network": "Network",
    "range": "Range",
    "port": "ProtocolPortObject",
    "network_group": "NetworkGroup",
}
PLAN_VERSION = 1


def identity(ref: dict[str, Any]) -> str:
    """Stable identity of a reference (object id, temp id or literal)."""
    if "id" in ref:
        return f"o:{ref['id']}"
    if "temp" in ref:
        return f"t:{ref['temp']}"
    return f"l:{ref.get('literal')}"


def item_ops(plan: dict[str, Any], item: int) -> list[dict[str, Any]]:
    """A plan's operations as they run inside a batch: its temp ids (``new:1`` ...) are numbered
    per plan, so they get the item's prefix — two plans in one batch never share an object."""
    ops: list[dict[str, Any]] = plan.get("ops", [])
    temps = {str(op["temp"]) for op in ops if "temp" in op}
    if not temps:
        return list(ops)

    def scoped(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: scoped(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scoped(v) for v in value]
        if isinstance(value, str) and value in temps:
            return f"i{item}/{value}"
        return value

    return [scoped(op) for op in ops]


class PlanBuilder:
    def __init__(self) -> None:
        self.ops: list[dict[str, Any]] = []
        self.blocked: list[str] = []
        self._temps = 0

    def temp(self) -> str:
        self._temps += 1
        return f"new:{self._temps}"

    def block(self, reason: str) -> None:
        if reason not in self.blocked:
            self.blocked.append(reason)

    @staticmethod
    def _rule(rule: dict[str, Any]) -> dict[str, Any]:
        return {
            "policy": rule["policy"],
            "policy_kind": rule["policy_kind"],
            "rule": rule["id"],
            "rule_name": rule["name"],
        }

    def _check_kind(self, rule: dict[str, Any]) -> None:
        if rule["policy_kind"] not in WRITABLE_RULE_KINDS:
            self.block(f"unsupported_rule_kind:{rule['policy_kind']}")

    def update_rule(
        self,
        rule: dict[str, Any],
        old: dict[str, list[dict[str, Any]]],
        new: dict[str, list[dict[str, Any]]],
        *,
        name: str | None = None,
    ) -> None:
        """Set the given fields (others untouched); ``old`` holds their current values."""
        self._check_kind(rule)
        changed = {
            f: v
            for f, v in new.items()
            if [identity(x) for x in v] != [identity(x) for x in old.get(f, [])]
        }
        if not changed and name is None:
            return
        op: dict[str, Any] = {
            "op": "update_rule",
            **self._rule(rule),
            "expect": {
                "name": rule["name"],
                "fields": {f: sorted(identity(x) for x in old.get(f, [])) for f in changed},
            },
            "set": changed,
        }
        if name is not None:
            op["name"] = name
        self.ops.append(op)

    def create_rule(
        self,
        source: dict[str, Any],
        source_fields: dict[str, list[dict[str, Any]]],
        *,
        insert_after: str,
        name: str,
        new: dict[str, list[dict[str, Any]]],
    ) -> str:
        """A copy of ``source`` (as found at execution) with ``new`` fields, placed after a rule."""
        self._check_kind(source)
        temp = self.temp()
        self.ops.append(
            {
                "op": "create_rule",
                "policy": source["policy"],
                "policy_kind": source["policy_kind"],
                "temp": temp,
                "copy_from": source["id"],
                "insert_after": insert_after,
                "name": name,
                "expect": {
                    "name": source["name"],
                    "fields": {
                        f: sorted(identity(x) for x in source_fields.get(f, [])) for f in new
                    },
                },
                "set": new,
            }
        )
        return temp

    def delete_rule(self, rule: dict[str, Any]) -> None:
        self._check_kind(rule)
        self.ops.append({"op": "delete_rule", **self._rule(rule), "expect": {"name": rule["name"]}})

    def create_object(
        self,
        kind: str,
        name: str,
        *,
        value: str | None = None,
        members: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        fmc_type = CREATABLE_TYPES.get(kind)
        if fmc_type is None:
            self.block(f"unsupported_object_kind:{kind}")
            fmc_type = kind
        temp = self.temp()
        op: dict[str, Any] = {
            "op": "create_object",
            "temp": temp,
            "kind": kind,
            "type": fmc_type,
            "name": name,
        }
        if value is not None:
            op["value"] = value
        if members is not None:
            op["members"] = members
        self.ops.append(op)
        return {"temp": temp, "type": fmc_type, "name": name}

    def update_group(
        self, group: dict[str, Any], old: list[dict[str, Any]], new: list[dict[str, Any]]
    ) -> None:
        self.ops.append(
            {
                "op": "update_group",
                "object": group["id"],
                "type": group["type"],
                "object_name": group["name"],
                "expect": {"name": group["name"], "members": sorted(identity(x) for x in old)},
                "members": new,
            }
        )

    def rename_object(self, obj: dict[str, Any], name: str) -> None:
        self.ops.append(
            {
                "op": "rename_object",
                "object": obj["id"],
                "type": obj["type"],
                "object_name": obj["name"],
                "expect": {"name": obj["name"]},
                "name": name,
            }
        )

    def delete_object(self, obj: dict[str, Any]) -> None:
        self.ops.append(
            {
                "op": "delete_object",
                "object": obj["id"],
                "type": obj["type"],
                "object_name": obj["name"],
                "expect": {"name": obj["name"]},
            }
        )

    def set_inspection(
        self,
        rule: dict[str, Any],
        current: dict[str, Any],
        *,
        ips: dict[str, Any] | None = None,
        file: dict[str, Any] | None = None,
        action: str | None = None,
    ) -> None:
        """Attach an intrusion and / or file policy to an access rule (``None``: keep).

        ``current`` holds the rule's ``action`` and its ``ips`` / ``file`` policy ids as in the
        snapshot; the executor stops if the FMC differs. ``action`` turns TRUST into ALLOW
        (trusted traffic skips Snort, so an intrusion policy needs an ALLOW rule).
        """
        if rule["policy_kind"] != "access":
            self.block(f"unsupported_rule_kind:{rule['policy_kind']}")
        if ips is None and file is None and action is None:
            return
        op: dict[str, Any] = {
            "op": "set_inspection",
            **self._rule(rule),
            "expect": {
                "name": rule["name"],
                "action": current["action"],
                "ips": current.get("ips"),
                "file": current.get("file"),
            },
        }
        if ips is not None:
            op["ips"] = {"id": ips["id"], "name": ips["name"], "type": "IntrusionPolicy"}
        if file is not None:
            op["file"] = {"id": file["id"], "name": file["name"], "type": "FilePolicy"}
        if action is not None:
            op["action"] = action
        self.ops.append(op)

    def build(self) -> dict[str, Any]:
        return {
            "version": PLAN_VERSION,
            "ops": self.ops,
            "executable": not self.blocked and bool(self.ops),
            "blocked": self.blocked,
        }


def touched(plan: dict[str, Any]) -> dict[str, set[str]]:
    """What a plan modifies, deletes and references (for changeset conflict checks)."""
    out: dict[str, set[str]] = {
        "rules": set(),
        "objects": set(),
        "deleted": set(),
        "referenced": set(),
    }
    for op in plan.get("ops", []):
        kind = op["op"]
        if kind in ("update_rule", "delete_rule", "set_inspection"):
            out["rules"].add(f"{op['policy']}/{op['rule']}")
        if kind == "create_rule":
            out["rules"].add(f"{op['policy']}/{op['copy_from']}")
        if kind in ("update_group", "rename_object", "delete_object"):
            out["objects"].add(op["object"])
        if kind == "delete_object":
            out["deleted"].add(op["object"])
        if kind == "delete_rule":
            out["deleted"].add(f"{op['policy']}/{op['rule']}")
        for refs in op.get("set", {}).values():
            out["referenced"] |= {r["id"] for r in refs if "id" in r}
        out["referenced"] |= {r["id"] for r in op.get("members", []) if "id" in r}
    return out
