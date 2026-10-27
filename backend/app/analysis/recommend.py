"""Phase 3: turn analysis results into concrete, doctrine-backed recommendations.

Every recommendation is a proposal on the local copy only — nothing is written to the
FMC. Each carries:

* a structured preview (``before`` / ``after`` rule views, and objects for object
  changes) that the UI renders inline or split, as the spec asks;
* its **deploy cost**: the number of FMC write operations it implies (object or rule
  create / update / delete; a rename is one update because rules reference by id);
* its expected impact: ACE delta (negative = saved) and rule-score delta;
* warnings the operator must weigh (e.g. names referenced outside the FMC);
* a fingerprint — stable while the rule / object and the proposal are unchanged — so an
  operator's decision survives the next pull and is dropped when the data changes.

Proposals are behaviour-preserving unless stated: removals target rules that can never
match or permit rules without hits (removing a *permit* only narrows access); splits and
merges keep the union of matched traffic and the evaluation order. Tightening narrows a
permit rule and is flagged for verification.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from statistics import mean
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from app.analysis.assets import effective_assets
from app.analysis.connectivity import NodeMapper, edges_for, rule_risk, worst
from app.analysis.expand import Leaves, Resolver, ace_estimate, build_space, literal_leaves
from app.analysis.naming import (
    MAX_NAME,
    Convention,
    disambiguate,
    port_tokens,
    service_name,
    value_token,
)
from app.analysis.score import PERMIT_ACTIONS, AssetIndex, RuleFacts, ScoreResult, score_rule
from app.analysis.semantic import load_assets
from app.analysis.shadow import verdict
from app.analysis.space import AddressSet, MatchSpace, PortSet
from app.enforce.plan import PlanBuilder, identity
from app.models.assets import RuleScore
from app.models.inventory import (
    ClusterPolicy,
    FwObject,
    GroupMember,
    Interface,
    Policy,
    Route,
    Rule,
    RuleRef,
    Snapshot,
)
from app.models.recommendations import NamingConvention, Recommendation
from app.workers import progress

TIER_ORDER = ("GOLD", "SILVER", "BRONZE", "CORE", "USERS", "UNCLASSIFIED")
UNCLASSIFIED = "UNCLASSIFIED"
ACE_KINDS = frozenset({"access", "prefilter"})
GROUP_KINDS = frozenset({"network_group", "port_group"})
ADDRESS_KINDS = frozenset({"host", "network", "range"})
WIDE_PORTS = 100
SAMPLE = 20  # affected rules listed in a preview
MAX_EXPAND_DEPTH = 8
_IPV4_IN_NAME = re.compile(r"\d{1,3}(?:[._-]\d{1,3}){3}")
_ASSET_PORT = re.compile(r"^(TCP|UDP|SCTP)[\s/:]*(\d{1,5})(?:-(\d{1,5}))?$", re.IGNORECASE)
_RULE_FIELDS_SHOWN = (
    "src_zone",
    "src_net",
    "src_sgt",
    "src_dyn",
    "user",
    "dst_zone",
    "dst_net",
    "dst_sgt",
    "dst_dyn",
    "src_port",
    "dst_port",
    "app",
    "url",
    "vlan",
)


# ------------------------------------------------------------------ data model


@dataclass(frozen=True)
class Ref:
    """One value in a rule field: an object reference or an inline literal."""

    object_id: str | None
    name: str
    literal: str | None = None
    literal_kind: str | None = None

    @property
    def label(self) -> str:
        return self.literal if self.literal is not None else self.name

    @property
    def identity(self) -> str:
        return f"o:{self.object_id}" if self.object_id is not None else f"l:{self.literal}"


@dataclass
class RuleInfo:
    rule: Rule
    refs: dict[str, list[Ref]]
    leaves: dict[str, Leaves]
    ace: int
    score: RuleScore | None

    @property
    def permit(self) -> bool:
        return self.rule.action in PERMIT_ACTIONS


@dataclass
class Draft:
    kind: str
    principle: str
    title: str
    priority: int
    display: str
    deploy_cost: int
    targets: list[dict[str, Any]]
    preview: dict[str, Any]
    policy_fmc_id: str | None = None
    ace_delta: int = 0
    score_delta: int | None = None
    warnings: list[str] = field(default_factory=list)
    # Executable FMC operations (app.enforce.plan); not part of the fingerprint.
    plan: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity of the proposal: what it touches and what it changes.

        Rule positions are left out on purpose — a rule inserted above must not void a
        decision — while any change to the involved rules or objects does.
        """
        body = json.dumps(
            {
                "kind": self.kind,
                "policy": self.policy_fmc_id,
                "targets": sorted(str(t.get("id")) for t in self.targets),
                "before": _positionless(self.preview.get("before", [])),
                "after": _positionless(self.preview.get("after", [])),
                "objects": self.preview.get("objects", {}),
                "rename": self.preview.get("rename"),
                "literal": self.preview.get("literal"),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(body.encode()).hexdigest()


def _positionless(views: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in view.items() if k != "index"} for view in views]


@dataclass(frozen=True)
class Obj:
    fmc_id: str
    name: str
    kind: str
    value: str | None
    stub: bool
    read_only: bool = False  # built-in FMC object: never deleted, renamed or edited

    @property
    def fixed(self) -> bool:
        """Not ours to change (stub or built-in)."""
        return self.stub or self.read_only


# ------------------------------------------------------------------ estate


class Estate:
    """Everything the recommenders need about one snapshot, loaded once."""

    def __init__(self, session: Session, snapshot_id: int) -> None:
        self.session = session
        self.snapshot_id = snapshot_id
        self.objects: dict[str, Obj] = {
            fid: Obj(fid, name, kind, value, stub, bool((attrs or {}).get("read_only")))
            for fid, name, kind, value, stub, attrs in session.execute(
                select(
                    FwObject.fmc_id,
                    FwObject.name,
                    FwObject.kind,
                    FwObject.value,
                    FwObject.stub,
                    FwObject.attrs,
                ).where(FwObject.snapshot_id == snapshot_id)
            ).all()
        }
        self.members: dict[str, list[Ref]] = defaultdict(list)
        self.parents: dict[str, set[str]] = defaultdict(set)
        for group, member, literal, literal_kind in session.execute(
            select(
                GroupMember.group_fmc_id,
                GroupMember.member_fmc_id,
                GroupMember.literal,
                GroupMember.literal_kind,
            )
            .where(GroupMember.snapshot_id == snapshot_id)
            .order_by(GroupMember.id)
        ).all():
            if member is not None:
                obj = self.objects.get(member)
                self.members[group].append(Ref(member, obj.name if obj else member))
                self.parents[member].add(group)
            elif literal is not None:
                self.members[group].append(Ref(None, literal, literal, literal_kind))
        self.resolver = Resolver.load(session, snapshot_id)
        self.assets: AssetIndex = load_assets(session)
        self.mapper = NodeMapper(self.assets)
        self.asset_rows = effective_assets(session)
        self.conventions: dict[str, Convention] = {
            c.kind: Convention(c.kind, c.template, c.letter_case)
            for c in session.scalars(
                select(NamingConvention).where(NamingConvention.enabled.is_(True))
            )
        }
        self.policies: dict[str, Policy] = {
            p.fmc_id: p
            for p in session.scalars(select(Policy).where(Policy.snapshot_id == snapshot_id))
        }
        # Direct rule references per object (rule db id, policy) and route usage.
        self.rule_users: dict[str, set[int]] = defaultdict(set)
        for oid, rule_id in session.execute(
            select(RuleRef.object_fmc_id, RuleRef.rule_id).where(
                RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id.is_not(None)
            )
        ).all():
            if oid is not None:
                self.rule_users[oid].add(rule_id)
        self.route_users: Counter[str] = Counter()
        for net_id, gw_id in session.execute(
            select(Route.network_fmc_id, Route.gateway_fmc_id).where(
                Route.snapshot_id == snapshot_id
            )
        ).all():
            for oid in (net_id, gw_id):
                if oid is not None:
                    self.route_users[oid] += 1
        self.zone_users: set[str] = {
            z
            for z in session.scalars(
                select(Interface.zone_fmc_id).where(Interface.snapshot_id == snapshot_id)
            )
            if z is not None
        }
        by_value: dict[tuple[str, str], list[Obj]] = defaultdict(list)
        for o in self.objects.values():
            if o.value and not o.stub:
                by_value[(o.kind, o.value)].append(o)
        self.by_value = by_value
        self.rule_headers: dict[int, tuple[str, int, str, str]] = {}
        # FMC "type" of every referenced object (needed in write payloads).
        self.types: dict[str, str] = {
            oid: t
            for oid, t in session.execute(
                select(RuleRef.object_fmc_id, RuleRef.object_type)
                .where(RuleRef.snapshot_id == snapshot_id, RuleRef.object_fmc_id.is_not(None))
                .distinct()
            ).all()
            if oid is not None and t
        }
        self.types.update(
            dict(
                session.execute(
                    select(FwObject.fmc_id, FwObject.fmc_type).where(
                        FwObject.snapshot_id == snapshot_id
                    )
                ).all()
            )
        )
        # (policy, zones) -> networks behind them; many rules share the same zones.
        self.zone_networks: dict[
            tuple[str, tuple[str, ...]], list[tuple[str, str | None, str]] | None
        ] = {}

    # ---- helpers

    def ref_json(self, ref: Ref) -> dict[str, Any]:
        """A reference as it goes into a plan (object with its FMC type, or a literal)."""
        if ref.object_id is not None:
            return {
                "id": ref.object_id,
                "type": self.types.get(ref.object_id, ""),
                "name": ref.name,
            }
        return {"literal": ref.literal, "literal_kind": ref.literal_kind}

    def refs_json(self, refs: Iterable[Ref]) -> list[dict[str, Any]]:
        return [self.ref_json(r) for r in refs]

    def obj_json(self, o: Obj) -> dict[str, Any]:
        return {"id": o.fmc_id, "type": self.types.get(o.fmc_id, ""), "name": o.name}

    def rule_records(
        self, rule_ids: Iterable[int]
    ) -> list[tuple[dict[str, Any], dict[str, list[Ref]]]]:
        """(rule identity, references per field) of rules given by database id."""
        ids = sorted(set(rule_ids))
        if not ids:
            return []
        heads: dict[int, dict[str, Any]] = {}
        refs: dict[int, dict[str, list[Ref]]] = defaultdict(lambda: defaultdict(list))
        for rid, fmc_id, name, policy, policy_kind in self.session.execute(
            select(Rule.id, Rule.fmc_id, Rule.name, Rule.policy_fmc_id, Rule.policy_kind).where(
                Rule.id.in_(ids)
            )
        ).all():
            heads[rid] = {"policy": policy, "policy_kind": policy_kind, "id": fmc_id, "name": name}
        for rid, fld, oid, oname, literal, literal_kind in self.session.execute(
            select(
                RuleRef.rule_id,
                RuleRef.field,
                RuleRef.object_fmc_id,
                RuleRef.object_name,
                RuleRef.literal,
                RuleRef.literal_kind,
            )
            .where(RuleRef.rule_id.in_(ids))
            .order_by(RuleRef.id)
        ).all():
            refs[rid][fld].append(Ref(oid, oname or (literal or ""), literal, literal_kind))
        return [(heads[rid], dict(refs[rid])) for rid in ids if rid in heads]

    def repoint(
        self,
        pb: PlanBuilder,
        replace: dict[str, list[dict[str, Any]]],
        *,
        rule_ids: Iterable[int],
        groups: Iterable[str],
        literal: tuple[str, str] | None = None,
    ) -> None:
        """Rewrite references: rules and groups pointing at replaced objects (or at an inline
        literal, ``(object kind, value)``) get the replacement references, deduplicated."""

        def rewrite(refs: list[Ref]) -> tuple[list[dict[str, Any]], bool]:
            out: list[dict[str, Any]] = []
            changed = False
            for r in refs:
                if r.object_id is not None and r.object_id in replace:
                    out += replace[r.object_id]
                    changed = True
                elif (
                    literal is not None
                    and r.literal is not None
                    and (_literal_object_kind(r.literal, r.literal_kind), r.literal) == literal
                ):
                    out += replace[f"literal:{literal[1]}"]
                    changed = True
                else:
                    out.append(self.ref_json(r))
            seen: set[str] = set()
            unique = []
            for x in out:
                if identity(x) not in seen:
                    seen.add(identity(x))
                    unique.append(x)
            return unique, changed

        for rule, fields in self.rule_records(rule_ids):
            old: dict[str, list[dict[str, Any]]] = {}
            new: dict[str, list[dict[str, Any]]] = {}
            for f, refs in fields.items():
                rewritten, changed = rewrite(refs)
                if changed:
                    old[f] = self.refs_json(refs)
                    new[f] = rewritten
            if new:
                pb.update_rule(rule, old, new)
        for gid in sorted(set(groups)):
            g = self.objects.get(gid)
            if g is None:
                continue
            members = self.members.get(gid, [])
            rewritten, changed = rewrite(members)
            if changed:
                pb.update_group(self.obj_json(g), self.refs_json(members), rewritten)
        for oid in replace:
            if self.route_users[oid]:
                pb.block("route_reference")

    def leaves_of(self, ref: Ref) -> Leaves:
        if ref.object_id is not None:
            return self.resolver.leaves(ref.object_id)
        return literal_leaves(ref.literal or "", ref.literal_kind)

    def tier_of(self, leaves: Leaves) -> str | None:
        """The single tier covering every address; UNCLASSIFIED; or None when mixed."""
        opaque = bool(leaves.address_tokens or leaves.tokens or leaves.ports)
        if not leaves.addresses:
            return UNCLASSIFIED if opaque else None
        addresses = AddressSet.build(leaves.addresses)
        touching = self.assets.touching(addresses)
        if not touching:
            return None if opaque else UNCLASSIFIED
        tiers = {e.tier for e in touching}
        if len(tiers) == 1 and not opaque and not self.assets.unclassified(addresses):
            return next(iter(tiers))
        return None

    def asset_facts(self, leaves: Leaves) -> dict[str, str | None]:
        """SYSTEM / TIER / TYPE / ROLE for an address set, when unambiguous."""
        out: dict[str, str | None] = {"SYSTEM": None, "TIER": None, "TYPE": None, "ROLE": None}
        if not leaves.addresses or leaves.address_tokens or leaves.tokens:
            return out
        addresses = AddressSet.build(leaves.addresses)
        if not len(self.assets) or self.assets.unclassified(addresses):
            return out
        touching = self.assets.touching(addresses)
        systems = {e.system for e in touching}
        tiers = {e.tier for e in touching}
        if len(tiers) == 1:
            out["TIER"] = next(iter(tiers))
        if len(systems) == 1:
            out["SYSTEM"] = next(iter(systems))
            types = {
                a.system_type
                for a in self.asset_rows
                if a.system in systems and a.system_type and a.tier in tiers
            }
            if len(types) == 1:
                out["TYPE"] = next(iter(types))
        out["ROLE"] = out["SYSTEM"] or out["TIER"]
        return out

    def endpoint_label(self, leaves: Leaves | None) -> str | None:
        """``SRC`` / ``DST`` token: system, else TIER-TYPE, else tier, else user type."""
        if leaves is None:
            return None
        addresses = AddressSet.build(leaves.addresses) if leaves.addresses else None
        if addresses is None or leaves.address_tokens or leaves.tokens:
            return None
        if not len(self.assets) or self.assets.unclassified(addresses):
            return None
        touching = self.assets.touching(addresses)
        systems = {e.system for e in touching}
        tiers = {e.tier for e in touching}
        if len(systems) == 1:
            return next(iter(systems))
        if tiers == {"USERS"}:
            user_types = {e.user_type for e in touching if e.user_type}
            return next(iter(user_types)) if len(user_types) == 1 else None
        if len(tiers) == 1:
            tier = next(iter(tiers))
            types = {
                a.system_type
                for a in self.asset_rows
                if a.tier == tier and a.system in systems and a.system_type
            }
            return f"{tier}-{next(iter(types))}" if len(types) == 1 else tier
        return None

    def object_refs(self, oid: str) -> tuple[set[int], set[str], int]:
        """(rules, parent groups, routes) referencing an object directly."""
        return self.rule_users.get(oid, set()), self.parents.get(oid, set()), self.route_users[oid]

    def existing_object(self, kind: str, value: str) -> Obj | None:
        found = sorted(self.by_value.get((kind, value), []), key=lambda o: o.name)
        return found[0] if found else None

    def rule_sample(self, rule_ids: Iterable[int]) -> list[dict[str, Any]]:
        ids = sorted(rule_ids)
        missing = [i for i in ids if i not in self.rule_headers]
        if missing:
            for rid, fmc_id, index, name, policy in self.session.execute(
                select(Rule.id, Rule.fmc_id, Rule.rule_index, Rule.name, Rule.policy_fmc_id).where(
                    Rule.id.in_(missing)
                )
            ).all():
                self.rule_headers[rid] = (fmc_id, index, name, policy)
        out = []
        for rid in ids[:SAMPLE]:
            header = self.rule_headers.get(rid)
            if header is None:
                continue
            fmc_id, index, name, policy = header
            p = self.policies.get(policy)
            out.append(
                {
                    "id": fmc_id,
                    "index": index,
                    "name": name,
                    "policy_id": policy,
                    "policy_name": p.name if p else policy,
                }
            )
        return out


# ------------------------------------------------------------------ rule views


def rule_view(
    info: RuleInfo,
    refs: dict[str, list[Ref]] | None = None,
    *,
    name: str | None = None,
    new: bool = False,
) -> dict[str, Any]:
    r = info.rule
    use = info.refs if refs is None else refs
    return {
        "id": None if new else r.fmc_id,
        "index": None if new else r.rule_index,
        "name": name or r.name,
        "action": r.action,
        "enabled": r.enabled,
        "section": r.section,
        "category": r.category,
        "fields": {f: [x.label for x in use[f]] for f in _RULE_FIELDS_SHOWN if use.get(f)},
    }


def with_status(
    view: dict[str, Any], status: str, before: dict[str, Any] | None = None
) -> dict[str, Any]:
    out = {**view, "status": status}
    if before is not None:
        changes: dict[str, dict[str, list[str]]] = {}
        for f in sorted(set(view["fields"]) | set(before["fields"])):
            old, new = before["fields"].get(f, []), view["fields"].get(f, [])
            added = [x for x in new if x not in old]
            removed = [x for x in old if x not in new]
            if added or removed:
                changes[f] = {"added": added, "removed": removed}
        if view["name"] != before["name"]:
            changes["name"] = {"added": [view["name"]], "removed": [before["name"]]}
        out["changes"] = changes
    return out


def _rule_dict(info: RuleInfo) -> dict[str, Any]:
    r = info.rule
    return {"policy": r.policy_fmc_id, "policy_kind": r.policy_kind, "id": r.fmc_id, "name": r.name}


def _plan(build: Any) -> dict[str, Any]:
    pb = PlanBuilder()
    build(pb)
    return pb.build()


def _rule_target(info: RuleInfo) -> dict[str, Any]:
    r = info.rule
    return {"type": "rule", "id": r.fmc_id, "name": r.name, "index": r.rule_index}


def _object_target(o: Obj) -> dict[str, Any]:
    return {"type": "object", "id": o.fmc_id, "name": o.name, "kind": o.kind}


# ------------------------------------------------------------------ evaluation


class Evaluator:
    """Re-score a rule with some fields replaced (the expected impact of a proposal)."""

    def __init__(self, estate: Estate) -> None:
        self.estate = estate

    def leaves(self, refs: dict[str, list[Ref]]) -> dict[str, Leaves]:
        out: dict[str, Leaves] = {}
        for f, values in refs.items():
            bucket = Leaves()
            for ref in values:
                bucket.update(self.estate.leaves_of(ref))
            out[f] = bucket
        return out

    def evaluate(
        self,
        info: RuleInfo,
        refs: dict[str, list[Ref]],
        *,
        overrides: dict[str, Any] | None = None,
    ) -> tuple[int, int | None]:
        """(ACE estimate, score) of the rule with these references (and other facts)."""
        ace, result, _space = self._assess(info, refs, overrides)
        return ace, (result.score if result is not None else None)

    def map_edges(self, info: RuleInfo, refs: dict[str, list[Ref]]) -> list[dict[str, str]]:
        """Map edges the rule would carry (none for deny, disabled or shadowed rules)."""
        if info.score is not None and info.score.shadowed_by is not None:
            return []
        _ace, result, space = self._assess(info, refs)
        if result is None or result.score is None:
            return []
        risk = rule_risk(str(x["code"]) for x in result.reasons)
        return edges_for(self.estate.mapper, space.src_net, space.dst_net, risk)

    def _assess(
        self,
        info: RuleInfo,
        refs: dict[str, list[Ref]],
        overrides: dict[str, Any] | None = None,
    ) -> tuple[int, ScoreResult | None, MatchSpace]:
        leaves = self.leaves(refs)
        space = build_space(leaves)
        ace = ace_estimate(leaves)
        r = info.rule
        if r.action not in PERMIT_ACTIONS or not r.enabled:
            return ace, None, space
        facts = RuleFacts(
            action=r.action,
            enabled=r.enabled,
            src=space.src_net,
            dst=space.dst_net,
            dst_ports_any=space.dst_port.any,
            dst_port_count=space.dst_port.port_count(),
            apps_any=space.token("app").any,
            ips_policy=r.ips_policy,
            file_policy=r.file_policy,
            log_end=r.log_end,
            log_begin=r.log_begin,
            hit_count=r.hit_count,
            dead=bool(info.score and info.score.dead),
            shadowed_by=info.score.shadowed_by if info.score else None,
            has_literals=any(x.literal is not None for v in refs.values() for x in v),
            ace_count=ace,
        )
        result = score_rule(replace(facts, **(overrides or {})), self.estate.assets)
        return ace, result, space


def map_preview(
    evaluator: Evaluator,
    before: list[tuple[RuleInfo, dict[str, list[Ref]]]],
    after: list[tuple[RuleInfo, dict[str, list[Ref]]]],
) -> dict[str, list[dict[str, str]]]:
    """Node-level edges before and after a rule change (the map's before / after view)."""

    def collect(pairs: list[tuple[RuleInfo, dict[str, list[Ref]]]]) -> list[dict[str, str]]:
        merged: dict[tuple[str, str], str] = {}
        for info, refs in pairs:
            for e in evaluator.map_edges(info, refs):
                key = (e["src"], e["dst"])
                merged[key] = worst(merged.get(key, "green"), e["risk"])
        return [{"src": s, "dst": d, "risk": r} for (s, d), r in sorted(merged.items())]

    return {"before": collect(before), "after": collect(after)}


def load_policy_rules(estate: Estate, policy_id: str) -> list[RuleInfo]:
    session, sid = estate.session, estate.snapshot_id
    rules = list(
        session.scalars(
            select(Rule)
            .where(Rule.snapshot_id == sid, Rule.policy_fmc_id == policy_id)
            .order_by(Rule.rule_index)
        )
    )
    if not rules:
        return []
    refs: dict[int, dict[str, list[Ref]]] = defaultdict(lambda: defaultdict(list))
    for rule_id, fld, oid, name, literal, literal_kind in session.execute(
        select(
            RuleRef.rule_id,
            RuleRef.field,
            RuleRef.object_fmc_id,
            RuleRef.object_name,
            RuleRef.literal,
            RuleRef.literal_kind,
        )
        .join(Rule, Rule.id == RuleRef.rule_id)
        .where(Rule.snapshot_id == sid, Rule.policy_fmc_id == policy_id)
        .order_by(RuleRef.id)
    ).all():
        refs[rule_id][fld].append(Ref(oid, name or (literal or ""), literal, literal_kind))
    scores = {
        s.rule_id: s
        for s in session.scalars(
            select(RuleScore).where(RuleScore.rule_id.in_([r.id for r in rules]))
        )
    }
    evaluator = Evaluator(estate)
    out = []
    for r in rules:
        rule_refs = {f: list(v) for f, v in refs.get(r.id, {}).items()}
        leaves = evaluator.leaves(rule_refs)
        estate.rule_headers[r.id] = (r.fmc_id, r.rule_index, r.name, r.policy_fmc_id)
        out.append(RuleInfo(r, rule_refs, leaves, ace_estimate(leaves), scores.get(r.id)))
    return out


def _reasons(info: RuleInfo) -> set[str]:
    return {str(x.get("code")) for x in (info.score.reasons if info.score else [])}


def _old_score(info: RuleInfo) -> int | None:
    return info.score.score if info.score else None


def _rule_priority(base: int, info: RuleInfo) -> int:
    score = _old_score(info)
    bonus = 0 if score is None else min(20, max(0, (100 - score) // 5))
    return min(100, base + bonus)


def _policy_ref(policy: Policy) -> dict[str, str]:
    return {"id": policy.fmc_id, "name": policy.name, "kind": policy.kind}


# ------------------------------------------------------------------ rule recommenders


def shadowed(info: RuleInfo) -> bool:
    """An earlier rule matches all of this rule's traffic: only its removal is proposed.

    Splitting, merging, tightening or renaming a rule that never matches would only add more
    rules that never match (seen in the lab: splits of shadowed copies created shadowed rules).
    """
    return info.score is not None and info.score.shadowed_by is not None


def recommend_removals(estate: Estate, policy: Policy, rules: list[RuleInfo]) -> list[Draft]:
    evaluator = Evaluator(estate)
    by_fmc = {i.rule.fmc_id: i for i in rules}
    drafts: list[Draft] = []
    for info in rules:
        r = info.rule
        if not r.enabled and policy.kind in ("access", "prefilter"):
            drafts.append(
                Draft(
                    kind="remove_disabled_rule",
                    principle="never_match",
                    title=f"Remove #{r.rule_index} {r.name}: disabled, matches nothing",
                    priority=45,
                    display="inline",
                    deploy_cost=1,
                    targets=[_rule_target(info)],
                    preview={
                        "policy": _policy_ref(policy),
                        "before": [rule_view(info)],
                        "after": [with_status(rule_view(info), "removed")],
                        "modified_at": r.modified_at.isoformat() if r.modified_at else None,
                    },
                    policy_fmc_id=policy.fmc_id,
                    ace_delta=0,
                    plan=_plan(lambda pb, info=info: pb.delete_rule(_rule_dict(info))),
                )
            )
            continue
        ace = info.ace if policy.kind in ACE_KINDS and r.enabled else 0
        shadow_id = info.score.shadowed_by if info.score else None
        if shadow_id is not None and r.enabled:
            by = by_fmc.get(shadow_id)
            if by is None:
                continue
            conflict = verdict(by.rule.action) != verdict(r.action)
            drafts.append(
                Draft(
                    kind="remove_shadowed_rule",
                    principle="never_match",
                    title=(
                        f"Remove #{r.rule_index} {r.name}: rule #{by.rule.rule_index} "
                        f"{by.rule.name} already matches all of its traffic"
                    ),
                    priority=85 if conflict else 75,
                    display="inline",
                    deploy_cost=1,
                    targets=[_rule_target(info)],
                    preview={
                        "policy": _policy_ref(policy),
                        "before": [rule_view(by), rule_view(info)],
                        "after": [
                            with_status(rule_view(by), "unchanged"),
                            with_status(rule_view(info), "removed"),
                        ],
                    },
                    policy_fmc_id=policy.fmc_id,
                    ace_delta=-ace,
                    warnings=["conflict_intent"] if conflict else [],
                    plan=_plan(lambda pb, info=info: pb.delete_rule(_rule_dict(info))),
                )
            )
            continue
        if policy.kind == "access" and info.score is not None and info.score.dead and info.permit:
            drafts.append(
                Draft(
                    kind="remove_dead_rule",
                    principle="rule_decay",
                    title=f"Remove #{r.rule_index} {r.name}: permit rule without hits",
                    priority=60,
                    display="inline",
                    deploy_cost=1,
                    targets=[_rule_target(info)],
                    preview={
                        "policy": _policy_ref(policy),
                        "before": [rule_view(info)],
                        "after": [with_status(rule_view(info), "removed")],
                        "hits": {
                            "hit_count": r.hit_count,
                            "last_hit": r.last_hit.isoformat() if r.last_hit else None,
                        },
                        "map": map_preview(evaluator, [(info, info.refs)], []),
                    },
                    policy_fmc_id=policy.fmc_id,
                    ace_delta=-ace,
                    warnings=["hit_counts_reset"],
                    plan=_plan(lambda pb, info=info: pb.delete_rule(_rule_dict(info))),
                )
            )
    return drafts


def _partition_by_tier(estate: Estate, refs: list[Ref]) -> tuple[dict[str, list[Ref]], bool] | None:
    """Destination references grouped by tier, descending into mixed groups.

    Returns ``(parts, expanded)`` or ``None`` when some single object spans several tiers
    (it cannot be split without changing what the rule matches).
    """
    parts: dict[str, list[Ref]] = defaultdict(list)
    expanded = False
    stack: list[tuple[Ref, int]] = [(ref, 0) for ref in reversed(refs)]
    seen: set[str] = set()
    while stack:
        ref, depth = stack.pop()
        tier = estate.tier_of(estate.leaves_of(ref))
        if tier is not None:
            if ref.identity not in {x.identity for x in parts[tier]}:
                parts[tier].append(ref)
            continue
        obj = estate.objects.get(ref.object_id or "")
        if obj is None or obj.kind not in GROUP_KINDS or depth >= MAX_EXPAND_DEPTH:
            return None
        if obj.fmc_id in seen:
            continue
        seen.add(obj.fmc_id)
        expanded = True
        stack.extend((m, depth + 1) for m in reversed(estate.members.get(obj.fmc_id, [])))
    return dict(parts), expanded


def _rule_name(
    estate: Estate,
    info: RuleInfo,
    refs: dict[str, list[Ref]],
    fallback: str,
    evaluator: Evaluator,
) -> str:
    convention = estate.conventions.get("rule")
    if convention is not None:
        leaves = evaluator.leaves(refs)
        values = _rule_tokens(estate, info, refs, leaves)
        rendered = convention.render(values)
        if rendered is not None:
            return rendered
    return fallback[:MAX_NAME]


def _rule_tokens(
    estate: Estate, info: RuleInfo, refs: dict[str, list[Ref]], leaves: dict[str, Leaves]
) -> dict[str, str | None]:
    dst = leaves.get("dst_net")
    ports = sorted(
        dst_port for x in refs.get("dst_port", []) for dst_port in _port_values(estate, x)
    )
    apps = [x.name for x in refs.get("app", [])]
    tier = estate.tier_of(dst) if dst is not None else None
    return {
        "SRC": estate.endpoint_label(leaves.get("src_net")),
        "DST": estate.endpoint_label(dst),
        "SVC": service_name(ports, apps) if not refs.get("url") else None,
        "TIER": tier if tier not in (None, UNCLASSIFIED) else None,
        "ACTION": info.rule.action,
    }


def _port_values(estate: Estate, ref: Ref) -> list[str]:
    leaves = estate.leaves_of(ref)
    return sorted(leaves.ports) if not leaves.tokens else []


def recommend_split_rules(estate: Estate, policy: Policy, rules: list[RuleInfo]) -> list[Draft]:
    evaluator = Evaluator(estate)
    drafts: list[Draft] = []
    taken = {i.rule.name for i in rules}
    for info in rules:
        r = info.rule
        if not (r.enabled and info.permit and "multi_tier_destination" in _reasons(info)):
            continue
        if shadowed(info):
            continue
        if info.refs.get("dst_sgt") or info.refs.get("dst_dyn") or not info.refs.get("dst_net"):
            continue
        partition = _partition_by_tier(estate, info.refs["dst_net"])
        if partition is None:
            continue
        parts, expanded = partition
        if len(parts) < 2:
            continue
        ordered = [t for t in TIER_ORDER if t in parts]
        before = rule_view(info)
        after: list[dict[str, Any]] = []
        aces: list[int] = []
        scores: list[int] = []
        names_used: set[str] = set(taken)
        after_pairs: list[tuple[RuleInfo, dict[str, list[Ref]]]] = []
        new_names: list[str] = []
        for n, tier in enumerate(ordered):
            refs = {**info.refs, "dst_net": parts[tier]}
            after_pairs.append((info, refs))
            ace, score = evaluator.evaluate(info, refs)
            aces.append(ace)
            if score is not None:
                scores.append(score)
            if n == 0:
                after.append(with_status(rule_view(info, refs), "modified", before))
                continue
            base = _rule_name(estate, info, refs, f"{r.name}_{tier}", evaluator)
            name = disambiguate(base, names_used)
            names_used.add(name)
            new_names.append(name)
            after.append(with_status(rule_view(info, refs, name=name, new=True), "new"))
        old = _old_score(info)
        warnings = ["group_expanded"] if expanded else []
        if UNCLASSIFIED in parts:
            warnings.append("unclassified_part")
        # The original rule keeps the first tier; the others are inserted right after it,
        # each copied from the (already narrowed) original.
        pb = PlanBuilder()
        rd = _rule_dict(info)
        first = {"dst_net": estate.refs_json(parts[ordered[0]])}
        pb.update_rule(rd, {"dst_net": estate.refs_json(info.refs["dst_net"])}, first)
        previous = r.fmc_id
        for tier, name in zip(ordered[1:], new_names, strict=True):
            previous = pb.create_rule(
                rd,
                first,
                insert_after=previous,
                name=name,
                new={"dst_net": estate.refs_json(parts[tier])},
            )
        drafts.append(
            Draft(
                kind="split_rule",
                principle="one_destination_tier",
                title=(
                    f"Split #{r.rule_index} {r.name} by destination tier: " + ", ".join(ordered)
                ),
                priority=_rule_priority(50, info),
                display="split",
                deploy_cost=len(ordered),  # 1 update + (n-1) creates
                targets=[_rule_target(info)],
                preview={
                    "policy": _policy_ref(policy),
                    "before": [before],
                    "after": after,
                    "map": map_preview(evaluator, [(info, info.refs)], after_pairs),
                },
                policy_fmc_id=policy.fmc_id,
                ace_delta=sum(aces) - info.ace,
                score_delta=(round(mean(scores)) - old) if scores and old is not None else None,
                warnings=warnings,
                plan=pb.build(),
            )
        )
    return drafts


def _merge_key(info: RuleInfo) -> tuple[Any, ...]:
    r = info.rule
    fields = tuple(
        (f, tuple(sorted(x.identity for x in values)))
        for f, values in sorted(info.refs.items())
        if f != "src_net" and values
    )
    return (
        r.section,
        r.category,
        r.action,
        r.ips_policy_id,
        r.file_policy_id,
        r.log_begin,
        r.log_end,
        fields,
    )


def recommend_merge_rules(estate: Estate, policy: Policy, rules: list[RuleInfo]) -> list[Draft]:
    """Adjacent permit rules identical except for their sources (same destination + service)."""
    evaluator = Evaluator(estate)
    drafts: list[Draft] = []
    run: list[RuleInfo] = []

    def eligible(i: RuleInfo) -> bool:
        return i.rule.enabled and i.permit and bool(i.refs.get("src_net"))

    def flush() -> None:
        if len(run) >= 2:
            drafts.append(_merge_draft(estate, evaluator, policy, list(run)))
        run.clear()

    for info in rules:
        if not info.rule.enabled or shadowed(info):
            continue  # neither takes part in evaluation: matches nothing in between
        if eligible(info) and run and _merge_key(run[-1]) == _merge_key(info):
            run.append(info)
            continue
        flush()
        if eligible(info):
            run.append(info)
    flush()
    return drafts


def _merge_draft(
    estate: Estate, evaluator: Evaluator, policy: Policy, run: list[RuleInfo]
) -> Draft:
    first = run[0]
    sources: list[Ref] = []
    seen: set[str] = set()
    for info in run:
        for ref in info.refs["src_net"]:
            if ref.identity not in seen:
                seen.add(ref.identity)
                sources.append(ref)
    refs = {**first.refs, "src_net": sources}
    ace, score = evaluator.evaluate(first, refs)
    before = [rule_view(i) for i in run]
    after = [with_status(rule_view(first, refs), "modified", before[0])]
    after += [with_status(rule_view(i), "removed") for i in run[1:]]
    olds = [s for s in (_old_score(i) for i in run) if s is not None]
    pb = PlanBuilder()
    pb.update_rule(
        _rule_dict(first),
        {"src_net": estate.refs_json(first.refs["src_net"])},
        {"src_net": estate.refs_json(sources)},
    )
    for i in run[1:]:
        pb.delete_rule(_rule_dict(i))
    return Draft(
        kind="merge_rules",
        principle="merge_same_intent",
        title=(
            f"Merge {len(run)} rules with the same destination and service: "
            + ", ".join(f"#{i.rule.rule_index}" for i in run[:6])
            + ("…" if len(run) > 6 else "")
        ),
        priority=40,
        display="split",
        deploy_cost=len(run),  # 1 update + (k-1) deletes
        targets=[_rule_target(i) for i in run],
        preview={
            "policy": _policy_ref(policy),
            "before": before,
            "after": after,
            "map": map_preview(evaluator, [(i, i.refs) for i in run], [(first, refs)]),
        },
        policy_fmc_id=policy.fmc_id,
        ace_delta=ace - sum(i.ace for i in run),
        score_delta=(score - round(mean(olds))) if score is not None and olds else None,
        plan=pb.build(),
    )


def _zone_networks(
    estate: Estate, policy: Policy, zone_ids: set[str]
) -> list[tuple[str, str | None, str]] | None:
    """(canonical network, object id, label) reachable through these zones; None on default."""
    key = (policy.fmc_id, tuple(sorted(zone_ids)))
    if key not in estate.zone_networks:
        estate.zone_networks[key] = _load_zone_networks(estate, policy, zone_ids)
    return estate.zone_networks[key]


def _load_zone_networks(
    estate: Estate, policy: Policy, zone_ids: set[str]
) -> list[tuple[str, str | None, str]] | None:
    session, sid = estate.session, estate.snapshot_id
    clusters = set(
        session.scalars(
            select(ClusterPolicy.cluster_fmc_id).where(
                ClusterPolicy.snapshot_id == sid, ClusterPolicy.policy_fmc_id == policy.fmc_id
            )
        )
    )
    if not clusters:
        return None
    interfaces = session.execute(
        select(Interface.cluster_fmc_id, Interface.name, Interface.ifname, Interface.ipv4).where(
            Interface.snapshot_id == sid,
            Interface.cluster_fmc_id.in_(clusters),
            Interface.zone_fmc_id.in_(zone_ids),
        )
    ).all()
    if not interfaces:
        return None
    found: dict[str, tuple[str, str | None, str]] = {}
    names: set[tuple[str, str]] = set()
    for cluster, name, ifname, ipv4 in interfaces:
        names.add((cluster, name))
        if ifname:
            names.add((cluster, ifname))
        if ipv4:
            net = str(ipaddress.ip_interface(ipv4).network)
            found.setdefault(net, (net, None, net))
    for cluster, iface, network, net_id, net_name in session.execute(
        select(
            Route.cluster_fmc_id,
            Route.interface,
            Route.network,
            Route.network_fmc_id,
            Route.network_name,
        ).where(Route.snapshot_id == sid, Route.cluster_fmc_id.in_(clusters))
    ).all():
        if (cluster, iface) not in names:
            continue
        if network is None:
            return None  # a route we cannot resolve: do not derive anything
        if ipaddress.ip_network(network).prefixlen == 0:
            return None  # default route behind the zone: "any" may be legitimate
        found[network] = (network, net_id, net_name or network)
    return sorted(found.values()) or None


def recommend_tighten(estate: Estate, policy: Policy, rules: list[RuleInfo]) -> list[Draft]:
    evaluator = Evaluator(estate)
    drafts: list[Draft] = []
    for info in rules:
        r = info.rule
        if not (r.enabled and info.permit) or shadowed(info):
            continue
        source_any = not any(info.refs.get(f) for f in ("src_net", "src_sgt", "src_dyn", "user"))
        zones = {x.object_id for x in info.refs.get("src_zone", []) if x.object_id}
        if source_any and zones:
            draft = _tighten_source(estate, evaluator, policy, info, zones)
            if draft is not None:
                drafts.append(draft)
        draft = _tighten_ports(estate, evaluator, policy, info)
        if draft is not None:
            drafts.append(draft)
    return drafts


def _network_ref(estate: Estate, network: str, object_id: str | None, label: str) -> Ref:
    if object_id is not None and object_id in estate.objects:
        return Ref(object_id, estate.objects[object_id].name)
    kind = "host" if network.endswith(("/32", "/128")) else "network"
    existing = estate.existing_object(kind, network)
    if existing is not None:
        return Ref(existing.fmc_id, existing.name)
    return Ref(None, label, network, "address")


def _tighten_source(
    estate: Estate, evaluator: Evaluator, policy: Policy, info: RuleInfo, zones: set[str]
) -> Draft | None:
    networks = _zone_networks(estate, policy, zones)
    if not networks:
        return None
    sources = [_network_ref(estate, n, oid, label) for n, oid, label in networks]
    refs = {**info.refs, "src_net": sources}
    ace, score = evaluator.evaluate(info, refs)
    old = _old_score(info)
    r = info.rule
    before = rule_view(info)
    warnings = ["derived_from_routing"]
    if any(x.literal is not None for x in sources):
        warnings.append("literal_needs_object")
    return Draft(
        kind="tighten_source",
        principle="least_privilege",
        title=(
            f"Tighten #{r.rule_index} {r.name}: replace any source with the "
            f"{len(sources)} network(s) behind its source zone(s)"
        ),
        priority=_rule_priority(55, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={
            "policy": _policy_ref(policy),
            "before": [before],
            "after": [with_status(rule_view(info, refs), "modified", before)],
            "map": map_preview(evaluator, [(info, info.refs)], [(info, refs)]),
        },
        policy_fmc_id=policy.fmc_id,
        ace_delta=ace - info.ace,
        score_delta=(score - old) if score is not None and old is not None else None,
        warnings=warnings,
        plan=_plan(
            lambda pb: pb.update_rule(
                _rule_dict(info),
                {"src_net": []},
                {"src_net": estate.refs_json(sources)},
            )
        ),
    )


def parse_asset_ports(text: str) -> list[str] | None:
    """``TCP 1433, UDP/53, tcp:8000-8080`` -> canonical specs; None if any token is unclear."""
    specs: list[str] = []
    for token in re.split(r"[,;]", text):
        token = token.strip()
        if not token:
            continue
        m = _ASSET_PORT.fullmatch(token)
        if m is None:
            return None
        low = int(m.group(2))
        high = int(m.group(3)) if m.group(3) else low
        if not 0 < low <= high <= 65535:
            return None
        proto = m.group(1).upper()
        specs.append(f"{proto}/{low}" if low == high else f"{proto}/{low}-{high}")
    return specs or None


def _tighten_ports(
    estate: Estate, evaluator: Evaluator, policy: Policy, info: RuleInfo
) -> Draft | None:
    dst = info.leaves.get("dst_net")
    if dst is None or not dst.addresses or dst.address_tokens or dst.tokens:
        return None
    if info.refs.get("app") or info.refs.get("url"):
        return None
    current = info.leaves.get("dst_port")
    current_set = PortSet(any=True) if current is None else PortSet.build(current.ports)
    if current is not None and (current.tokens or current.address_tokens):
        return None
    count = current_set.port_count()
    if not (current_set.any or (count is not None and count > WIDE_PORTS)):
        return None
    addresses = AddressSet.build(dst.addresses)
    if not len(estate.assets) or estate.assets.unclassified(addresses):
        return None
    touching = estate.assets.touching(addresses)
    systems = {e.system for e in touching}
    rows = [a for a in estate.asset_rows if a.system in systems]
    specs: set[str] = set()
    for a in rows:
        parsed = parse_asset_ports(a.ports)
        if parsed is None:
            return None  # an asset without (clear) declared ports: no basis to tighten
        specs.update(parsed)
    proposal = PortSet.build(specs)
    if not current_set.covers(proposal) or proposal.covers(current_set):
        return None  # never widen, and only propose a real reduction
    ports: list[Ref] = []
    for spec in sorted(specs):
        existing = estate.existing_object("port", spec)
        ports.append(
            Ref(existing.fmc_id, existing.name) if existing else Ref(None, spec, spec, "port")
        )
    refs = {**info.refs, "dst_port": ports}
    ace, score = evaluator.evaluate(info, refs)
    old = _old_score(info)
    r = info.rule
    before = rule_view(info)
    warnings = ["asset_ports_declared"]
    if any(x.literal is not None for x in ports):
        warnings.append("literal_needs_object")
    return Draft(
        kind="tighten_ports",
        principle="stingy_service",
        title=(
            f"Tighten #{r.rule_index} {r.name}: open only the declared service ports "
            + ", ".join(sorted(specs)[:6])
        ),
        priority=_rule_priority(50, info),
        display="inline",
        deploy_cost=1,
        targets=[_rule_target(info)],
        preview={
            "policy": _policy_ref(policy),
            "before": [before],
            "after": [with_status(rule_view(info, refs), "modified", before)],
            "map": map_preview(evaluator, [(info, info.refs)], [(info, refs)]),
        },
        policy_fmc_id=policy.fmc_id,
        ace_delta=ace - info.ace,
        score_delta=(score - old) if score is not None and old is not None else None,
        warnings=warnings,
        plan=_plan(
            lambda pb: pb.update_rule(
                _rule_dict(info),
                {"dst_port": estate.refs_json(info.refs.get("dst_port", []))},
                {"dst_port": estate.refs_json(ports)},
            )
        ),
    )


# ------------------------------------------------------------------ object recommenders


def _keep_order(estate: Estate, o: Obj) -> tuple[int, int, int, int, str]:
    """Which duplicate survives: one used by static routes first (routes are device settings the
    writer does not repoint), then the most referenced, convention-compliant, shortest name."""
    rules, parents, routes = estate.object_refs(o.fmc_id)
    convention = estate.conventions.get(o.kind)
    compliant = 0 if convention is not None and convention.complies(o.name) else 1
    return (
        0 if o.read_only or routes else 1,  # a built-in object can only be the survivor
        -(len(rules) + len(parents) + routes),
        compliant,
        len(o.name),
        o.name,
    )


def _merge_objects_draft(
    estate: Estate, kind: str, principle: str, group: Sequence[Obj], why: str
) -> Draft:
    ordered = sorted(group, key=lambda o: _keep_order(estate, o))
    keep, others = ordered[0], ordered[1:]
    rules: set[int] = set()
    parents: set[str] = set()
    routes = 0
    for o in others:
        r, p, n = estate.object_refs(o.fmc_id)
        rules |= r
        parents |= p
        routes += n
    parents -= {o.fmc_id for o in others}
    pb = PlanBuilder()
    keep_ref = estate.obj_json(keep)
    estate.repoint(
        pb,
        {o.fmc_id: [keep_ref] for o in others},
        rule_ids=rules,
        groups=parents,
    )
    for o in others:
        pb.delete_object(estate.obj_json(o))

    def obj_view(o: Obj, status: str) -> dict[str, Any]:
        r, p, n = estate.object_refs(o.fmc_id)
        return {
            "id": o.fmc_id,
            "name": o.name,
            "kind": o.kind,
            "value": o.value,
            "members": [m.label for m in estate.members.get(o.fmc_id, [])][:SAMPLE],
            "references": len(r) + len(p) + n,
            "status": status,
        }

    return Draft(
        kind=kind,
        principle=principle,
        title=(
            f"Merge {len(group)} {keep.kind} objects ({why}) into {keep.name}: "
            + ", ".join(o.name for o in others[:5])
            + ("…" if len(others) > 5 else "")
        ),
        priority=30 if kind == "merge_duplicate_objects" else 35,
        display="split",
        deploy_cost=len(rules) + len(parents) + routes + len(others),
        targets=[_object_target(o) for o in ordered],
        preview={
            "objects": {
                "before": [obj_view(o, "unchanged") for o in ordered],
                "after": [obj_view(keep, "kept")] + [obj_view(o, "removed") for o in others],
            },
            "affected_rules": {"total": len(rules), "sample": estate.rule_sample(rules)},
            "affected_groups": sorted(
                estate.objects[g].name for g in parents if g in estate.objects
            ),
        },
        warnings=["external_references"],
        plan=pb.build(),
    )


def _reachable(estate: Estate, start: str) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        oid = stack.pop()
        for m in estate.members.get(oid, []):
            if m.object_id is not None and m.object_id not in seen:
                seen.add(m.object_id)
                stack.append(m.object_id)
    return seen


def recommend_object_merges(estate: Estate) -> list[Draft]:
    drafts: list[Draft] = []
    for (kind, value), objs in sorted(estate.by_value.items()):
        if len(objs) > 1 and kind not in GROUP_KINDS and sum(o.read_only for o in objs) < 2:
            drafts.append(
                _merge_objects_draft(
                    estate, "merge_duplicate_objects", "one_name_per_value", objs, f"value {value}"
                )
            )
    by_leaves: dict[tuple[str, frozenset[str]], list[Obj]] = defaultdict(list)
    for o in estate.objects.values():
        if o.kind not in GROUP_KINDS or o.stub:
            continue
        leaves = estate.resolver.leaves(o.fmc_id)
        if leaves.tokens or leaves.address_tokens:
            continue
        values = frozenset(leaves.addresses | leaves.ports)
        if values:
            by_leaves[(o.kind, values)].append(o)
    for (_kind, _values), objs in sorted(by_leaves.items(), key=lambda kv: kv[1][0].name):
        ids = {o.fmc_id for o in objs}
        # A group wrapping another candidate (e.g. GRP_10.30.0.0 = [GRP_SYS_APP]) has the same
        # content but cannot be merged with what it contains (self-reference): leave the
        # wrappers out and merge the rest.
        objs = [o for o in objs if not (_reachable(estate, o.fmc_id) & (ids - {o.fmc_id}))]
        if len(objs) < 2 or sum(o.read_only for o in objs) > 1:
            continue
        drafts.append(
            _merge_objects_draft(estate, "merge_groups", "one_name_per_value", objs, "same members")
        )
    return drafts


def recommend_split_groups(estate: Estate) -> list[Draft]:
    drafts: list[Draft] = []
    convention = estate.conventions.get("network_group")
    taken = {o.name for o in estate.objects.values()}
    for o in sorted(estate.objects.values(), key=lambda x: x.name):
        if o.kind != "network_group" or o.fixed or not estate.rule_users.get(o.fmc_id):
            continue
        parts: dict[str, list[Ref]] = defaultdict(list)
        splittable = True
        for m in estate.members.get(o.fmc_id, []):
            tier = estate.tier_of(estate.leaves_of(m))
            if tier is None:
                splittable = False
                break
            parts[tier].append(m)
        if not splittable or len([t for t in parts if t != UNCLASSIFIED]) < 2:
            continue
        ordered = [t for t in TIER_ORDER if t in parts]
        new_groups = []
        pb = PlanBuilder()
        created: list[dict[str, Any]] = []
        for tier in ordered:
            rendered = (
                convention.render({"TIER": tier, "ROLE": tier, "SYSTEM": None, "TYPE": None})
                if convention is not None
                else None
            )
            name = disambiguate(rendered or f"{o.name}_{tier}"[:MAX_NAME], taken)
            taken.add(name)
            created.append(
                pb.create_object("network_group", name, members=estate.refs_json(parts[tier]))
            )
            new_groups.append(
                {
                    "id": None,
                    "name": name,
                    "kind": o.kind,
                    "tier": tier,
                    "members": [m.label for m in parts[tier]],
                    "status": "new",
                }
            )
        rules, parents, routes = estate.object_refs(o.fmc_id)
        estate.repoint(pb, {o.fmc_id: created}, rule_ids=rules, groups=parents)
        pb.delete_object(estate.obj_json(o))
        drafts.append(
            Draft(
                kind="split_group",
                principle="group_by_role",
                title=f"Split group {o.name} by tier: " + ", ".join(ordered),
                priority=45,
                display="split",
                deploy_cost=len(ordered) + len(rules) + len(parents) + routes + 1,
                targets=[_object_target(o)],
                preview={
                    "objects": {
                        "before": [
                            {
                                "id": o.fmc_id,
                                "name": o.name,
                                "kind": o.kind,
                                "members": [m.label for m in estate.members.get(o.fmc_id, [])],
                                "status": "unchanged",
                            }
                        ],
                        "after": [
                            *new_groups,
                            {"id": o.fmc_id, "name": o.name, "kind": o.kind, "status": "removed"},
                        ],
                    },
                    "affected_rules": {"total": len(rules), "sample": estate.rule_sample(rules)},
                    "affected_groups": sorted(
                        estate.objects[g].name for g in parents if g in estate.objects
                    ),
                },
                warnings=["external_references"]
                + (["unclassified_part"] if UNCLASSIFIED in parts else []),
                plan=pb.build(),
            )
        )
    return drafts


def _object_tokens(estate: Estate, o: Obj) -> dict[str, str | None]:
    values: dict[str, str | None] = {"VALUE": value_token(o.kind, o.value)}
    if o.kind in ADDRESS_KINDS or o.kind == "network_group":
        values.update(estate.asset_facts(estate.resolver.leaves(o.fmc_id)))
    if o.kind == "port":
        proto, port = port_tokens(o.value)
        values["PROTO"], values["PORT"] = proto, port
        values["SVC"] = service_name([o.value] if o.value else [], [])
    if o.kind == "port_group":
        leaves = estate.resolver.leaves(o.fmc_id)
        values["SVC"] = service_name(leaves.ports, []) if not leaves.tokens else None
    return values


def _rename_draft(
    estate: Estate, o: Obj, new_name: str, kind: str, principle: str, warnings: list[str]
) -> Draft:
    rules, parents, routes = estate.object_refs(o.fmc_id)
    return Draft(
        kind=kind,
        principle=principle,
        title=f"Rename {o.kind} {o.name} to {new_name}",
        priority=20 if kind == "rename_role" else 15,
        display="inline",
        deploy_cost=1,  # rules and groups reference the object by id
        targets=[_object_target(o)],
        preview={
            "rename": {"from": o.name, "to": new_name, "kind": o.kind},
            "affected_rules": {"total": len(rules), "sample": estate.rule_sample(rules)},
            "affected_groups": sorted(
                estate.objects[g].name for g in parents if g in estate.objects
            ),
            "routes": routes,
        },
        warnings=["external_references", *warnings],
        plan=_plan(lambda pb: pb.rename_object(estate.obj_json(o), new_name)),
    )


def recommend_renames(estate: Estate) -> tuple[list[Draft], dict[str, dict[str, int]]]:
    """Role names for IP-named groups, then the admin naming convention (objects)."""
    drafts: list[Draft] = []
    stats: dict[str, dict[str, int]] = {}
    taken = {o.name for o in estate.objects.values()}
    renamed: set[str] = set()
    for o in sorted(estate.objects.values(), key=lambda x: x.name):
        if o.fixed or o.kind != "network_group" or not _IPV4_IN_NAME.search(o.name):
            continue
        facts = estate.asset_facts(estate.resolver.leaves(o.fmc_id))
        convention = estate.conventions.get(o.kind)
        proposed = (
            convention.render(_object_tokens(estate, o))
            if convention is not None
            else (f"GRP_{facts['ROLE']}" if facts["ROLE"] else None)
        )
        if proposed is None or proposed == o.name:
            continue
        name = disambiguate(proposed, taken - {o.name})
        taken.add(name)
        renamed.add(o.fmc_id)
        extra = ["name_disambiguated"] if name != proposed else []
        drafts.append(_rename_draft(estate, o, name, "rename_role", "role_names", extra))
    for kind, convention in sorted(estate.conventions.items()):
        if kind == "rule":
            continue
        counts = {"compliant": 0, "noncompliant": 0, "proposed": 0}
        for o in sorted(estate.objects.values(), key=lambda x: x.name):
            if o.kind != kind or o.fixed:
                continue
            if convention.complies(o.name):
                counts["compliant"] += 1
                continue
            counts["noncompliant"] += 1
            if o.fmc_id in renamed:
                continue
            proposed = convention.render(_object_tokens(estate, o))
            if proposed is None or proposed == o.name:
                continue
            name = disambiguate(proposed, taken - {o.name})
            taken.add(name)
            counts["proposed"] += 1
            extra = ["name_disambiguated"] if name != proposed else []
            drafts.append(
                _rename_draft(estate, o, name, "rename_convention", "naming_convention", extra)
            )
        stats[kind] = counts
    return drafts, stats


def recommend_rule_renames(
    estate: Estate, policy: Policy, rules: list[RuleInfo], stats: dict[str, dict[str, int]]
) -> list[Draft]:
    convention = estate.conventions.get("rule")
    if convention is None or policy.kind != "access":
        return []
    counts = stats.setdefault("rule", {"compliant": 0, "noncompliant": 0, "proposed": 0})
    taken = {i.rule.name for i in rules}
    drafts: list[Draft] = []
    for info in rules:
        r = info.rule
        if convention.complies(r.name):
            counts["compliant"] += 1
            continue
        counts["noncompliant"] += 1
        if shadowed(info):
            continue  # removed instead
        proposed = convention.render(_rule_tokens(estate, info, info.refs, info.leaves))
        if proposed is None or proposed == r.name:
            continue
        name = disambiguate(proposed, taken - {r.name})
        taken.add(name)
        counts["proposed"] += 1
        before = rule_view(info)
        drafts.append(
            Draft(
                kind="rename_convention",
                principle="naming_convention",
                title=f"Rename rule #{r.rule_index} {r.name} to {name}",
                priority=15,
                display="inline",
                deploy_cost=1,
                targets=[_rule_target(info)],
                preview={
                    "policy": _policy_ref(policy),
                    "before": [before],
                    "after": [with_status(rule_view(info, name=name), "modified", before)],
                },
                policy_fmc_id=policy.fmc_id,
                score_delta=0,
                warnings=["external_references"]
                + (["name_disambiguated"] if name != proposed else []),
                plan=_plan(
                    lambda pb, info=info, name=name: pb.update_rule(
                        _rule_dict(info), {}, {}, name=name
                    )
                ),
            )
        )
    return drafts


def proposed_object_name(estate: Estate, kind: str, value: str) -> str | None:
    """The naming-convention name (or the default) for a new object holding ``value``."""
    convention = estate.conventions.get(kind)
    tokens: dict[str, str | None] = {"VALUE": value_token(kind, value)}
    if kind in ADDRESS_KINDS:
        tokens.update(
            estate.asset_facts(literal_leaves(value, "address" if kind != "range" else "range"))
        )
    else:
        tokens.update(_object_tokens(estate, Obj("", "", kind, value, False)))
    return (convention.render(tokens) if convention else None) or _default_literal_name(kind, value)


def _default_literal_name(kind: str, value: str) -> str | None:
    if kind == "host":
        return f"H_{value.split('/', 1)[0]}"
    if kind == "network":
        return f"NET_{value.replace('/', '-')}"
    if kind == "range":
        return f"RNG_{value}"
    if kind == "port":
        proto, port = port_tokens(value)
        return f"SVC_{proto}{port}" if proto and port else None
    return None


def _literal_object_kind(literal: str, literal_kind: str | None) -> str | None:
    if literal_kind == "range":
        return "range"
    if literal_kind == "address":
        return "host" if literal.endswith(("/32", "/128")) else "network"
    if literal_kind == "port":
        return "port"
    return None


def recommend_literals(estate: Estate) -> list[Draft]:
    """Inline rule values -> an (existing or new, convention-named) object."""
    session, sid = estate.session, estate.snapshot_id
    uses: dict[tuple[str, str], set[int]] = defaultdict(set)
    for literal, literal_kind, rule_id in session.execute(
        select(RuleRef.literal, RuleRef.literal_kind, RuleRef.rule_id).where(
            RuleRef.snapshot_id == sid, RuleRef.literal.is_not(None)
        )
    ).all():
        if literal is None:
            continue
        kind = _literal_object_kind(literal, literal_kind)
        if kind is not None:
            uses[(kind, literal)].add(rule_id)
    taken = {o.name for o in estate.objects.values()}
    drafts: list[Draft] = []
    for (kind, value), rules in sorted(uses.items()):
        existing = estate.existing_object(kind, value)
        create = existing is None
        pb = PlanBuilder()
        if existing is not None:
            name = existing.name
        else:
            proposed = proposed_object_name(estate, kind, value)
            if proposed is None:
                continue
            name = disambiguate(proposed[:MAX_NAME], taken)
            taken.add(name)
        target = (
            estate.obj_json(existing)
            if existing is not None
            else pb.create_object(kind, name, value=value)
        )
        estate.repoint(
            pb, {f"literal:{value}": [target]}, rule_ids=rules, groups=(), literal=(kind, value)
        )
        drafts.append(
            Draft(
                kind="literal_to_object",
                principle="no_literals",
                title=(
                    f"Replace inline {value} in {len(rules)} rule(s) with "
                    + ("new" if create else "existing")
                    + f" object {name}"
                ),
                priority=25,
                display="inline",
                deploy_cost=len(rules) + (1 if create else 0),
                targets=[{"type": "literal", "id": f"{kind}:{value}", "name": value, "kind": kind}],
                preview={
                    "literal": {
                        "value": value,
                        "kind": kind,
                        "object": name,
                        "object_id": existing.fmc_id if existing else None,
                        "create": create,
                    },
                    "affected_rules": {"total": len(rules), "sample": estate.rule_sample(rules)},
                },
                plan=pb.build(),
            )
        )
    return drafts


def recommend_unused(estate: Estate) -> list[Draft]:
    drafts = []
    for o in sorted(estate.objects.values(), key=lambda x: (x.kind, x.name)):
        if o.fixed:
            continue
        rules, parents, routes = estate.object_refs(o.fmc_id)
        if rules or parents or routes or o.fmc_id in estate.zone_users:
            continue
        drafts.append(
            Draft(
                kind="remove_unused_object",
                principle="rule_decay",
                title=f"Remove unused {o.kind} {o.name}",
                priority=10,
                display="inline",
                deploy_cost=1,
                targets=[_object_target(o)],
                preview={
                    "objects": {
                        "before": [
                            {
                                "id": o.fmc_id,
                                "name": o.name,
                                "kind": o.kind,
                                "value": o.value,
                                "status": "unchanged",
                            }
                        ],
                        "after": [
                            {
                                "id": o.fmc_id,
                                "name": o.name,
                                "kind": o.kind,
                                "value": o.value,
                                "status": "removed",
                            }
                        ],
                    }
                },
                warnings=["external_references"],
                plan=_plan(lambda pb, o=o: pb.delete_object(estate.obj_json(o))),
            )
        )
    return drafts


# ------------------------------------------------------------------ entry point


def recommend(session: Session, snapshot_id: int) -> dict[str, int]:
    """Recompute all recommendations of a snapshot (idempotent). Caller commits."""
    session.execute(delete(Recommendation).where(Recommendation.snapshot_id == snapshot_id))
    # Phase-6 inspection builds on this module's primitives (imported here: no cycle).
    from app.analysis import compact, inspection, redundancy

    estate = Estate(session, snapshot_id)
    drafts: list[Draft] = []
    renames, naming_stats = recommend_renames(estate)
    profiles = inspection.load_profiles(session)
    ssl = inspection.SslAdvisor(estate)
    ordered = sorted(estate.policies.values(), key=lambda p: (p.kind, p.name))
    ace_rules: dict[int, RuleInfo] = {}
    for n, policy in enumerate(ordered):
        progress.advance(n, len(ordered))
        if policy.kind not in ("access", "prefilter", "decryption"):
            continue
        rules = load_policy_rules(estate, policy.fmc_id)
        if not rules:
            continue
        drafts += recommend_removals(estate, policy, rules)
        if policy.kind in ACE_KINDS:
            ace_rules.update((info.rule.id, info) for info in rules)
        if policy.kind in ("access", "prefilter"):
            drafts += redundancy.recommend_redundant_references(estate, policy, rules)
        if policy.kind == "access":
            drafts += recommend_split_rules(estate, policy, rules)
            drafts += recommend_merge_rules(estate, policy, rules)
            drafts += recommend_tighten(estate, policy, rules)
            drafts += recommend_rule_renames(estate, policy, rules, naming_stats)
            drafts += inspection.recommend_inspection(estate, policy, rules, profiles)
            ssl.access(policy, rules)
        elif policy.kind == "decryption":
            ssl.decryption_policy(policy, rules)
    drafts += ssl.drafts()
    drafts += recommend_object_merges(estate)
    members = redundancy.recommend_redundant_members(estate)
    drafts += members
    drafts += compact.recommend_compact_groups(
        estate, ace_rules, skip={t["id"] for d in members for t in d.targets}
    )
    drafts += recommend_split_groups(estate)
    drafts += renames
    drafts += recommend_literals(estate)
    drafts += recommend_unused(estate)

    if drafts:
        session.execute(
            insert(Recommendation),
            [
                {
                    "snapshot_id": snapshot_id,
                    "kind": d.kind,
                    "policy_fmc_id": d.policy_fmc_id,
                    "title": d.title[:512],
                    "principle": d.principle,
                    "priority": d.priority,
                    "targets": d.targets,
                    "preview": d.preview,
                    "display": d.display,
                    "deploy_cost": d.deploy_cost,
                    "ace_delta": d.ace_delta,
                    "score_delta": d.score_delta,
                    "warnings": d.warnings,
                    "fingerprint": d.fingerprint(),
                    "plan": d.plan,
                }
                for d in drafts
            ],
        )
    summary = dict(Counter(d.kind for d in drafts))
    snap = session.get(Snapshot, snapshot_id)
    if snap is not None:
        session.execute(
            update(Snapshot)
            .where(Snapshot.id == snapshot_id)
            .values(stats={**snap.stats, "recommendations": summary, "naming": naming_stats})
        )
    return summary
