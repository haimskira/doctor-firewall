"""Traffic proof: does a batch change what any flow gets?

The firewall decides each flow by the first enabled rule that matches it (MONITOR rules log and
let evaluation continue; no match: the policy's default action). For every policy a batch can
affect, this module builds the rulebase *before* (the snapshot) and *after* (the batch's plan
applied to it, or what the FMC holds after writing — see :func:`model_from_fmc`) and compares
the verdicts — action, intrusion policy, file policy — of probe flows.

Which flows are enough
----------------------
A flow whose verdict changes is matched, before or after, by a rule the batch *touched*: a rule
created, deleted or rewritten, or one whose objects changed (a group's members, nested at any
depth). So only the region of touched rules is probed. Inside it, every dimension (source and
destination address, service, source port, zones / applications / users / ...) is cut at the
boundaries of all rules overlapping the region: within one cell of that grid no rule starts or
ends, so every rule matches all of the cell or none of it, and one flow per cell decides the
cell. The probe flows are one point per cell — when their number stays under the cap the check
is **exhaustive** (a proof for the modelled dimensions); above it the grid is thinned evenly and
the report says the check was sampled.

Not modelled: application *detection* inside allowed services, URL categories by reputation,
time ranges. Rules that use them are compared on their listed values.
"""

from __future__ import annotations

import copy
import itertools
import time
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.expand import Leaves, Resolver, build_space, literal_leaves
from app.analysis.space import ALL_PROTOCOLS, AddressSet, MatchSpace, PortSet, TokenSet
from app.models.inventory import FwObject, GroupMember, Policy, Rule, RuleRef

SPACE_FIELDS = (
    "src_zone",
    "dst_zone",
    "src_net",
    "dst_net",
    "src_port",
    "dst_port",
    "app",
    "url",
    "src_sgt",
    "dst_sgt",
    "src_dyn",
    "dst_dyn",
    "user",
    "vlan",
)
TOKEN_DIMS = (
    "src_zone",
    "dst_zone",
    "app",
    "url",
    "src_sgt",
    "dst_sgt",
    "src_dyn",
    "dst_dyn",
    "user",
    "vlan",
)
PROVABLE_KINDS = ("access", "prefilter")
PASS_THROUGH = frozenset({"MONITOR"})
# Above this many cells per touched rule the grid is thinned (and the proof marked sampled).
MAX_CELLS_PER_RULE = 20_000
MAX_DIFFERENCES = 50
V4_TOP = 2**32 - 1
V6_TOP = 2**128 - 1

Member = tuple[str | None, str | None, str | None]  # (object id, literal, literal kind)


@dataclass
class RuleModel:
    key: str  # FMC id, or "temp:<id>" for a rule the batch creates
    name: str
    enabled: bool
    action: str
    ips: str | None
    file: str | None
    refs: dict[str, list[Member]] = field(default_factory=dict)


@dataclass
class PolicyModel:
    fmc_id: str
    name: str
    kind: str
    default_action: str
    rules: list[RuleModel]


@dataclass
class Model:
    objects: dict[str, tuple[str, str | None]]
    members: dict[str, list[Member]]
    policies: dict[str, PolicyModel]

    def resolver(self) -> Resolver:
        return Resolver(self.objects, self.members)

    def clone(self) -> Model:
        return Model(
            objects=dict(self.objects),
            members={k: list(v) for k, v in self.members.items()},
            policies=copy.deepcopy(self.policies),
        )


# ------------------------------------------------------------------ the model


def load_model(session: Session, snapshot_id: int) -> Model:
    """The snapshot's objects, groups and every access / prefilter rulebase, in order."""
    objects = {
        fid: (kind, value)
        for fid, kind, value in session.execute(
            select(FwObject.fmc_id, FwObject.kind, FwObject.value).where(
                FwObject.snapshot_id == snapshot_id
            )
        )
    }
    members: dict[str, list[Member]] = defaultdict(list)
    for group, member, literal, literal_kind in session.execute(
        select(
            GroupMember.group_fmc_id,
            GroupMember.member_fmc_id,
            GroupMember.literal,
            GroupMember.literal_kind,
        )
        .where(GroupMember.snapshot_id == snapshot_id)
        .order_by(GroupMember.id)
    ):
        members[group].append((member, literal, literal_kind))
    policies: dict[str, PolicyModel] = {}
    for p in session.scalars(
        select(Policy).where(Policy.snapshot_id == snapshot_id, Policy.kind.in_(PROVABLE_KINDS))
    ):
        policies[p.fmc_id] = PolicyModel(p.fmc_id, p.name, p.kind, p.default_action.upper(), [])
    by_rule: dict[int, RuleModel] = {}
    for r in session.scalars(
        select(Rule)
        .where(Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id.in_(list(policies)))
        .order_by(Rule.policy_fmc_id, Rule.rule_index)
    ):
        model = RuleModel(
            key=r.fmc_id,
            name=r.name,
            enabled=r.enabled,
            action=r.action.upper(),
            ips=r.ips_policy_id,
            file=r.file_policy_id,
        )
        by_rule[r.id] = model
        policies[r.policy_fmc_id].rules.append(model)
    for rule_id, fld, oid, literal, literal_kind in session.execute(
        select(
            RuleRef.rule_id,
            RuleRef.field,
            RuleRef.object_fmc_id,
            RuleRef.literal,
            RuleRef.literal_kind,
        )
        .where(RuleRef.snapshot_id == snapshot_id, RuleRef.field.in_(SPACE_FIELDS))
        .order_by(RuleRef.id)
    ):
        owner = by_rule.get(rule_id)
        if owner is not None:
            owner.refs.setdefault(fld, []).append((oid, literal, literal_kind))
    return Model(objects, dict(members), policies)


def _ref_member(ref: dict[str, Any]) -> Member:
    if "temp" in ref:
        return (f"temp:{ref['temp']}", None, None)
    if "id" in ref:
        return (str(ref["id"]), None, None)
    return (None, str(ref.get("literal")), ref.get("literal_kind"))


def _literal_kind(kind: str | None) -> str | None:
    return {"host": "address", "network": "address", "range": "range", "port": "port"}.get(
        kind or "", kind
    )


def apply_plan(model: Model, ops: list[dict[str, Any]]) -> Model:
    """The model after a batch's operations (the plan as the executor will carry it out)."""
    after = model.clone()
    for op in ops:
        kind = op.get("op")
        if kind == "create_object":
            key = f"temp:{op['temp']}"
            okind = str(op.get("kind"))
            if okind == "network_group":
                after.objects[key] = ("network_group", None)
                after.members[key] = [_ref_member(m) for m in op.get("members", [])]
            else:
                value = str(op.get("value") or "")
                if okind == "host" and "/" not in value:
                    value = f"{value}/128" if ":" in value else f"{value}/32"
                after.objects[key] = (okind, value)
        elif kind == "update_group":
            after.members[str(op["object"])] = [_ref_member(m) for m in op.get("members", [])]
        elif kind == "delete_object":
            after.objects.pop(str(op["object"]), None)
            after.members.pop(str(op["object"]), None)
        elif kind == "rename_object":
            continue
        elif kind in ("update_rule", "delete_rule", "set_inspection", "create_rule"):
            policy = after.policies.get(str(op.get("policy")))
            if policy is None:
                continue  # a policy kind the proof does not model (never written either)
            rules = policy.rules
            if kind == "create_rule":
                source = next(r for r in rules if r.key == str(op["copy_from"]))
                new = copy.deepcopy(source)
                new.key, new.name = f"temp:{op['temp']}", str(op["name"])
                for fld, refs in op.get("set", {}).items():
                    new.refs[fld] = [_ref_member(x) for x in refs]
                anchor = str(op["insert_after"])
                if anchor.startswith("new:"):
                    anchor = f"temp:{anchor}"
                at = next(i for i, r in enumerate(rules) if r.key == anchor)
                rules.insert(at + 1, new)
                continue
            target = next(r for r in rules if r.key == str(op["rule"]))
            if kind == "delete_rule":
                rules.remove(target)
            elif kind == "update_rule":
                for fld, refs in op.get("set", {}).items():
                    target.refs[fld] = [_ref_member(x) for x in refs]
                target.name = str(op.get("name", target.name))
            else:
                if "action" in op:
                    target.action = str(op["action"]).upper()
                if "ips" in op:
                    target.ips = str(op["ips"]["id"])
                if "file" in op:
                    target.file = str(op["file"]["id"])
    return after


def _leaves(rule: RuleModel, resolver: Resolver) -> dict[str, Leaves]:
    out: dict[str, Leaves] = {}
    for fld, refs in rule.refs.items():
        bucket = out.setdefault(fld, Leaves())
        for oid, literal, literal_kind in refs:
            if oid is not None:
                bucket.update(resolver.leaves(oid))
            elif literal is not None:
                bucket.update(literal_leaves(literal, _literal_kind(literal_kind)))
    return out


def spaces(policy: PolicyModel, resolver: Resolver) -> dict[str, MatchSpace]:
    return {r.key: build_space(_leaves(r, resolver)) for r in policy.rules}


# ------------------------------------------------------------------ flows and verdicts

Point = tuple[int, int] | str  # (IP version, integer) or an opaque token (FQDN, stub object)


@dataclass(frozen=True)
class Flow:
    src: Point
    dst: Point
    service: tuple[str, int] | str  # (protocol, port) or a service token (e.g. ICMP/8)
    sport: int | None
    tokens: tuple[tuple[str, str | None], ...]


def _addr_in(addresses: AddressSet, point: Point) -> bool:
    if addresses.any:
        return True
    if isinstance(point, str):
        return point in addresses.tokens
    version, value = point
    intervals = addresses.v4 if version == 4 else addresses.v6
    i = bisect_right(intervals, (value, V6_TOP + 1)) - 1
    return i >= 0 and intervals[i][0] <= value <= intervals[i][1]


def _port_ranges(ports: PortSet, proto: str) -> tuple[tuple[int, int], ...]:
    found = dict(ports.by_protocol)
    return tuple(sorted(found.get(proto, ()) + found.get(ALL_PROTOCOLS, ())))


def _svc_in(ports: PortSet, service: tuple[str, int] | str) -> bool:
    if ports.any:
        return True
    full = dict(ports.by_protocol).get(ALL_PROTOCOLS) == ((0, 65535),)
    if isinstance(service, str):
        return service in ports.tokens or full
    proto, port = service
    return any(lo <= port <= hi for lo, hi in _port_ranges(ports, proto))


def _sport_in(ports: PortSet, flow: Flow) -> bool:
    if ports.any:
        return True
    if flow.sport is None or isinstance(flow.service, str):
        return False
    return any(lo <= flow.sport <= hi for lo, hi in _port_ranges(ports, flow.service[0]))


def _token_in(tokens: TokenSet, value: str | None) -> bool:
    return tokens.any or (value is not None and value in tokens.tokens)


def contains(space: MatchSpace, flow: Flow) -> bool:
    if not (_addr_in(space.src_net, flow.src) and _addr_in(space.dst_net, flow.dst)):
        return False
    if not _svc_in(space.dst_port, flow.service) or not _sport_in(space.src_port, flow):
        return False
    values = dict(flow.tokens)
    return all(_token_in(space.token(d), values.get(d)) for d in TOKEN_DIMS)


def verdict(rule: RuleModel) -> tuple[str, str | None, str | None]:
    """What a flow gets from a rule: inspection only matters for traffic that is let through."""
    if rule.action.startswith("BLOCK") or rule.action in ("TRUST", "FASTPATH"):
        return (rule.action, None, None)
    return (rule.action, rule.ips, rule.file)


def first_match(
    rules: list[tuple[RuleModel, MatchSpace]], flow: Flow, default: str
) -> tuple[tuple[str, str | None, str | None], str | None]:
    for rule, space in rules:
        if not rule.enabled or rule.action in PASS_THROUGH:
            continue
        if contains(space, flow):
            return verdict(rule), rule.name
    return (f"DEFAULT:{default}", None, None), None


# ------------------------------------------------------------------ probe grid


def _cuts(intervals: list[tuple[int, int]], low: int, high: int) -> set[int]:
    """Cell starts inside [low, high]: each interval's start and the value after its end."""
    out = {low}
    for lo, hi in intervals:
        for p in (lo, hi + 1):
            if low <= p <= high:
                out.add(p)
    return out


def _address_points(region: list[AddressSet], around: list[AddressSet]) -> list[Point]:
    points: set[Point] = set()
    for version, top in ((4, V4_TOP), (6, V6_TOP)):
        cuts_from = [iv for a in around if not a.any for iv in (a.v4 if version == 4 else a.v6)]
        spans: list[tuple[int, int]] = []
        for a in region:
            if a.any:
                if version == 4 or any(x.v6 for x in around):  # IPv6 only if a rule uses it
                    spans.append((0, top))
            else:
                spans.extend(a.v4 if version == 4 else a.v6)
        for lo, hi in spans:
            points.update((version, p) for p in _cuts(cuts_from, lo, hi))
    tokens = {t for a in region for t in a.tokens}
    if any(a.any for a in region):
        tokens |= {t for a in around for t in a.tokens}
    points.update(tokens)
    return sorted(points, key=lambda p: (isinstance(p, str), str(p)))


def _service_points(region: list[PortSet], around: list[PortSet]) -> list[tuple[str, int] | str]:
    protos = {p for ps in region + around for p, _ in ps.by_protocol if p != ALL_PROTOCOLS}
    if not protos:
        protos = {"TCP"}
    points: set[tuple[str, int] | str] = set()
    for proto in protos:
        cuts_from = [iv for ps in around if not ps.any for iv in _port_ranges(ps, proto)]
        spans: list[tuple[int, int]] = []
        for ps in region:
            spans.extend([(0, 65535)] if ps.any else _port_ranges(ps, proto))
        for lo, hi in spans:
            points.update((proto, p) for p in _cuts(cuts_from, lo, hi))
    tokens = {t for ps in region for t in ps.tokens}
    if any(ps.any for ps in region):
        tokens |= {t for ps in around for t in ps.tokens}
    points.update(tokens)
    return sorted(points, key=lambda p: (isinstance(p, str), str(p)))


def _sport_points(region: list[PortSet], around: list[PortSet]) -> list[int | None]:
    if all(ps.any for ps in region + around):
        return [None]
    cuts_from = [iv for ps in around if not ps.any for _p, ivs in ps.by_protocol for iv in ivs]
    spans = [(0, 65535)] if any(ps.any for ps in region) else []
    for ps in region:
        if not ps.any:
            spans.extend(iv for _p, ivs in ps.by_protocol for iv in ivs)
    out: set[int] = set()
    for lo, hi in spans:
        out |= _cuts(cuts_from, lo, hi)
    return [*sorted(out)]


def _token_points(dim: str, region: list[MatchSpace], around: list[MatchSpace]) -> list[str | None]:
    sets = [s.token(dim) for s in region]
    values: set[str | None] = {t for ts in sets for t in ts.tokens}
    if any(ts.any for ts in sets):
        values |= {t for s in around for t in s.token(dim).tokens}
        values.add(None)  # a value no rule lists
    return sorted(values, key=lambda v: (v is None, v or ""))


def _thin(values: list[Any], keep: int) -> list[Any]:
    if len(values) <= keep:
        return values
    step = len(values) / keep
    return [values[int(i * step)] for i in range(keep)]


def probe_flows(region: list[MatchSpace], around: list[MatchSpace]) -> tuple[list[Flow], bool]:
    """One flow per cell of the region's grid (thinned above the cap): (flows, exhaustive)."""
    dims: list[list[Any]] = [
        _address_points([s.src_net for s in region], [s.src_net for s in around]),
        _address_points([s.dst_net for s in region], [s.dst_net for s in around]),
        _service_points([s.dst_port for s in region], [s.dst_port for s in around]),
        _sport_points([s.src_port for s in region], [s.src_port for s in around]),
        *[_token_points(d, region, around) for d in TOKEN_DIMS],
    ]
    cells = 1
    for d in dims:
        cells *= max(1, len(d))
    exhaustive = cells <= MAX_CELLS_PER_RULE
    while cells > MAX_CELLS_PER_RULE:
        widest = max(range(len(dims)), key=lambda i: len(dims[i]))
        dims[widest] = _thin(dims[widest], max(1, len(dims[widest]) // 2))
        cells = 1
        for d in dims:
            cells *= max(1, len(d))
    flows = []
    for combo in itertools.product(*dims):
        src, dst, service, sport, *tokens = combo
        flows.append(
            Flow(
                src=src,
                dst=dst,
                service=service,
                sport=sport,
                tokens=tuple(zip(TOKEN_DIMS, tokens, strict=True)),
            )
        )
    return flows, exhaustive


# ------------------------------------------------------------------ the proof


def describe_flow(flow: Flow) -> dict[str, Any]:
    import ipaddress

    def point(p: Point) -> str:
        if isinstance(p, str):
            return p
        version, value = p
        return str(ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value))

    service = (
        flow.service if isinstance(flow.service, str) else f"{flow.service[0]}/{flow.service[1]}"
    )
    return {
        "src": point(flow.src),
        "dst": point(flow.dst),
        "service": service,
        **({"src_port": flow.sport} if flow.sport is not None else {}),
        **{d: v for d, v in flow.tokens if v is not None},
    }


def compare(before: Model, after: Model, policy_ids: set[str] | None = None) -> dict[str, Any]:
    """Every flow whose verdict differs between two models, policy by policy."""
    started = time.monotonic()
    rb, ra = before.resolver(), after.resolver()
    report: dict[str, Any] = {"policies": [], "flows": 0, "differences": 0, "exhaustive": True}
    for pid, pb in before.policies.items():
        if policy_ids is not None and pid not in policy_ids:
            continue
        pa = after.policies.get(pid)
        if pa is None:
            continue
        sb, sa = spaces(pb, rb), spaces(pa, ra)
        rules_b = {r.key: r for r in pb.rules}
        rules_a = {r.key: r for r in pa.rules}
        touched = sorted(
            k
            for k in set(rules_b) | set(rules_a)
            if k not in rules_b
            or k not in rules_a
            or sb[k] != sa[k]
            or verdict(rules_b[k]) != verdict(rules_a[k])
            or rules_b[k].enabled != rules_a[k].enabled
        )
        entry: dict[str, Any] = {
            "id": pid,
            "name": pb.name,
            "touched": len(touched),
            "flows": 0,
            "exhaustive": True,
            "differences": [],
        }
        report["policies"].append(entry)
        if not touched:
            continue
        ordered_b = [(r, sb[r.key]) for r in pb.rules]
        ordered_a = [(r, sa[r.key]) for r in pa.rules]
        seen: set[Flow] = set()
        found = 0
        for key in touched:
            region = [s for s in (sb.get(key), sa.get(key)) if s is not None]
            near_b = [(r, s) for r, s in ordered_b if any(s.intersects(x) for x in region)]
            near_a = [(r, s) for r, s in ordered_a if any(s.intersects(x) for x in region)]
            around = [s for _r, s in near_b + near_a]
            flows, exhaustive = probe_flows(region, around)
            entry["exhaustive"] = entry["exhaustive"] and exhaustive
            for flow in flows:
                if flow in seen or not any(contains(s, flow) for s in region):
                    continue
                seen.add(flow)
                vb, nb = first_match(near_b, flow, pb.default_action)
                va, na = first_match(near_a, flow, pa.default_action)
                if vb != va:
                    found += 1
                    if len(entry["differences"]) < MAX_DIFFERENCES:
                        entry["differences"].append(
                            {
                                "flow": describe_flow(flow),
                                "before": {"verdict": list(vb), "rule": nb},
                                "after": {"verdict": list(va), "rule": na},
                            }
                        )
        entry["flows"] = len(seen)
        entry["difference_count"] = found
        report["flows"] += len(seen)
        report["differences"] += found
        report["exhaustive"] = report["exhaustive"] and entry["exhaustive"]
    report["ok"] = report["differences"] == 0
    report["seconds"] = round(time.monotonic() - started, 2)
    report["policies"] = [p for p in report["policies"] if p["touched"]]
    return report
