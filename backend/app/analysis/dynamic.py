"""Dynamic-object candidates: large address lists in access rules that a dynamic object could
carry instead (``use_dynamic_object``). Advisory only — never staged or executed.

A network group with at least :data:`DYNAMIC_MIN` addresses (its leaves, through every nested
group), or a rule side that lists that many objects directly, is a candidate. The addresses are
cross-checked with the content of every dynamic object collected from the FMC (its mappings at
collection time):

* **identical** — a dynamic object maps exactly these addresses: use it instead of the group;
* **close** — a dynamic object holds at least :data:`MATCH_SHARE` of them: shown with what it
  lacks and what it would add, so the operator decides;
* **none** — no dynamic object is close: create one for these addresses (a suggested name is
  given) and let the orchestrator / connector that owns the list keep it current.

The recommendation never changes anything: its plan is blocked (``dynamic_object_manual``) so it
can be accepted as a decision but never staged. A dynamic object's content changes at runtime,
outside the FMC and without a deploy — every proposal says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from app.analysis.recommend import (
    Draft,
    Estate,
    Ref,
    RuleInfo,
    _object_target,
    _plan,
    _policy_ref,
    _rule_priority,
    _rule_target,
    rule_view,
    shadowed,
    with_status,
)
from app.analysis.space import AddressSet
from app.models.inventory import FwObject, Policy

DYNAMIC_MIN = 50  # addresses (or objects listed in a rule side) that make a candidate
MATCH_SHARE = 0.8  # share of the addresses a dynamic object must hold to be proposed
SAMPLE = 20  # addresses listed as missing / extra
SIDES = (("src_net", "src_dyn"), ("dst_net", "dst_dyn"))
NAME_PREFIX = "DYN-"


@dataclass
class DynamicObject:
    fmc_id: str
    name: str
    addresses: list[str]
    space: AddressSet
    total: int  # mappings on the FMC (only the first ones are kept beyond a limit)

    @property
    def truncated(self) -> bool:
        return self.total > len(self.addresses)


@dataclass
class Match:
    obj: DynamicObject | None
    kind: str  # identical | close | none
    covered: int = 0
    missing: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)


class DynamicCatalog:
    """The dynamic objects of a snapshot and their mapped addresses, loaded once."""

    def __init__(self, estate: Estate) -> None:
        self.items: list[DynamicObject] = []
        self._single: dict[str, AddressSet] = {}
        self.suggested: set[str] = set()  # new names proposed in this run (lower case)
        for fid, name, attrs in estate.session.execute(
            select(FwObject.fmc_id, FwObject.name, FwObject.attrs).where(
                FwObject.snapshot_id == estate.snapshot_id,
                FwObject.kind == "dynamic",
                FwObject.stub.is_(False),
            )
        ).all():
            raw = list((attrs or {}).get("mappings") or [])
            mapped = [m for m in raw if self._valid(m)]
            if not mapped:
                continue
            # The total counts hostnames too: take out the ones seen (beyond the kept part the
            # split is unknown, so a cut list stays "truncated").
            total = int((attrs or {}).get("mappings_total") or len(raw)) - (len(raw) - len(mapped))
            self.items.append(
                DynamicObject(
                    fid,
                    name,
                    sorted(set(mapped)),
                    AddressSet.build(mapped),
                    max(total, len(mapped)),
                )
            )

    def _valid(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        try:
            self.one(value)
        except ValueError:
            return False  # a hostname mapping: not an address
        return True

    def one(self, address: str) -> AddressSet:
        found = self._single.get(address)
        if found is None:
            found = AddressSet.build([address])
            self._single[address] = found
        return found

    def best(self, addresses: list[str], space: AddressSet, *, opaque: bool = False) -> Match:
        """The dynamic object closest to ``addresses`` (identical first, then the largest share
        held, then the fewest extra addresses)."""
        best: tuple[tuple[int, float, int], Match] | None = None
        for d in self.items:
            if not d.space.intersects(space):
                continue
            missing = [a for a in addresses if not d.space.covers(self.one(a))]
            share = 1 - len(missing) / len(addresses)
            if share < MATCH_SHARE:
                continue
            extra = [m for m in d.addresses if not space.covers(self.one(m))]
            identical = not missing and not extra and not d.truncated and not opaque
            rank = (int(identical), share, -len(extra))
            if best is None or rank > best[0]:
                best = (
                    rank,
                    Match(
                        d,
                        "identical" if identical else "close",
                        len(addresses) - len(missing),
                        missing,
                        extra,
                    ),
                )
        return best[1] if best is not None else Match(None, "none")


def _suggested_name(estate: Estate, catalog: DynamicCatalog, base: str) -> str:
    taken = {o.name.lower() for o in estate.objects.values()} | catalog.suggested
    name = NAME_PREFIX + base[: 64 - len(NAME_PREFIX)]
    n = 2
    while name.lower() in taken:
        name = f"{NAME_PREFIX}{base[:56]}-{n}"
        n += 1
    catalog.suggested.add(name.lower())
    return name


def _swap(info: RuleInfo, removed: set[str], replacement: Ref) -> dict[str, list[Ref]]:
    """The rule's references with the removed ones taken out of each network side and the
    dynamic object added to the matching dynamic side (only where something was removed)."""
    refs = {f: list(v) for f, v in info.refs.items()}
    for net_field, dyn_field in SIDES:
        kept = [r for r in refs.get(net_field, []) if r.identity not in removed]
        if len(kept) == len(refs.get(net_field, [])):
            continue
        refs[net_field] = kept
        if replacement.identity not in {r.identity for r in refs.get(dyn_field, [])}:
            refs[dyn_field] = [*refs.get(dyn_field, []), replacement]
    return refs


def _dynamic_preview(
    match: Match, name: str, addresses: list[str], tokens: int, source: dict[str, Any]
) -> dict[str, Any]:
    d = match.obj
    return {
        "match": match.kind,
        "name": name,
        "id": d.fmc_id if d is not None else None,
        "create": d is None,
        "source": source,
        "addresses": len(addresses),
        "covered": match.covered if d is not None else 0,
        "missing": match.missing[:SAMPLE],
        "missing_count": len(match.missing),
        "extra": match.extra[:SAMPLE],
        "extra_count": len(match.extra),
        "mapped": len(d.addresses) if d is not None else 0,
        "mapped_total": d.total if d is not None else 0,
        "truncated": bool(d is not None and d.truncated),
        "not_mappable": tokens,
        "sample": addresses[:SAMPLE],
    }


def _warnings(match: Match, tokens: int) -> list[str]:
    out = ["dynamic_runtime_content"]
    if match.missing:
        out.append("dynamic_missing_addresses")
    if match.extra:
        out.append("dynamic_extra_addresses")
    if match.obj is not None and match.obj.truncated:
        out.append("dynamic_mappings_truncated")
    if tokens:
        out.append("dynamic_fqdn_stays")
    return out


def _title(match: Match, what: str, count: int, rules: int) -> str:
    where = f"in {rules} rule" + ("s" if rules != 1 else "")
    if match.obj is None:
        return f"Consider a dynamic object for {what} ({count} addresses) {where}"
    if match.kind == "identical":
        return f"Use dynamic object {match.obj.name} for {what}: same {count} addresses, {where}"
    share = round(100 * match.covered / count)
    return (
        f"Dynamic object {match.obj.name} holds {share}% of {what} ({count} addresses):"
        f" consider it {where}"
    )


def recommend_dynamic_objects(
    estate: Estate, policy: Policy, rules: list[RuleInfo], catalog: DynamicCatalog
) -> list[Draft]:
    """``use_dynamic_object`` for one access policy (its own rules only)."""
    live = [i for i in rules if i.rule.enabled and not shadowed(i) and not i.unmodelled]
    cyclic = estate.cyclic_groups()
    drafts: list[Draft] = []

    # 1. Large groups referenced directly in a network side: one proposal per group.
    users: dict[str, dict[int, RuleInfo]] = {}
    for info in live:
        for net_field, _dyn in SIDES:
            for ref in info.refs.get(net_field, []):
                oid = ref.object_id
                if oid is None:
                    continue
                o = estate.objects.get(oid)
                if o is None or o.kind != "network_group" or o.stub or o.overridable:
                    continue
                if oid in cyclic:
                    continue
                users.setdefault(oid, {})[info.rule.id] = info
    big: set[str] = set()
    for oid, by_rule in sorted(users.items(), key=lambda kv: estate.objects[kv[0]].name):
        o = estate.objects[oid]
        infos = sorted(by_rule.values(), key=lambda i: i.rule.rule_index)
        leaves = estate.resolver.leaves(oid)
        addresses = sorted(leaves.addresses)
        if len(addresses) < DYNAMIC_MIN:
            continue
        big.add(oid)
        space = AddressSet.build(addresses)
        tokens = len(leaves.address_tokens)
        match = catalog.best(addresses, space, opaque=tokens > 0)
        name = match.obj.name if match.obj is not None else _suggested_name(estate, catalog, o.name)
        replacement = Ref(match.obj.fmc_id if match.obj is not None else None, name)
        drafts.append(
            _draft(
                estate,
                policy,
                infos,
                {f"o:{oid}"},
                replacement,
                match,
                title=_title(match, f"group {o.name}", len(addresses), len(infos)),
                dynamic=_dynamic_preview(
                    match,
                    name,
                    addresses,
                    tokens,
                    {"type": "group", "id": oid, "name": o.name},
                ),
                extra_targets=[_object_target(o)],
                tokens=tokens,
            )
        )

    # 2. A rule side that lists many objects directly (no big group behind them).
    for info in live:
        for net_field, _dyn in SIDES:
            refs = [r for r in info.refs.get(net_field, []) if r.object_id not in big]
            if len(refs) < DYNAMIC_MIN:
                continue
            found: set[str] = set()
            tokens = 0
            for ref in refs:
                leaves = estate.leaves_of(ref)
                found |= leaves.addresses
                tokens += len(leaves.address_tokens)
            addresses = sorted(found)
            if len(addresses) < DYNAMIC_MIN:
                continue
            space = AddressSet.build(addresses)
            match = catalog.best(addresses, space, opaque=tokens > 0)
            side = "source" if net_field == "src_net" else "destination"
            rule = info.rule
            name = (
                match.obj.name
                if match.obj is not None
                else _suggested_name(
                    estate, catalog, f"{rule.name}-{'SRC' if side == 'source' else 'DST'}"
                )
            )
            replacement = Ref(match.obj.fmc_id if match.obj is not None else None, name)
            drafts.append(
                _draft(
                    estate,
                    policy,
                    [info],
                    {x.identity for x in refs},
                    replacement,
                    match,
                    title=_title(
                        match, f"the {side} of #{rule.rule_index} {rule.name}", len(addresses), 1
                    ),
                    dynamic=_dynamic_preview(
                        match,
                        name,
                        addresses,
                        tokens,
                        {"type": "rule", "id": rule.fmc_id, "name": rule.name, "side": side},
                    ),
                    extra_targets=[],
                    tokens=tokens,
                    field_only=net_field,
                )
            )
    return drafts


def _draft(
    estate: Estate,
    policy: Policy,
    infos: list[RuleInfo],
    removed: set[str],
    replacement: Ref,
    match: Match,
    *,
    title: str,
    dynamic: dict[str, Any],
    extra_targets: list[dict[str, Any]],
    tokens: int,
    field_only: str | None = None,
) -> Draft:
    befores: list[dict[str, Any]] = []
    afters: list[dict[str, Any]] = []
    for info in infos[:SAMPLE]:
        before = rule_view(info)
        if field_only is not None:  # only this side moves (the other may list the same objects)
            refs = {f: list(v) for f, v in info.refs.items()}
            dyn_field = dict(SIDES)[field_only]
            refs[field_only] = [r for r in refs[field_only] if r.identity not in removed]
            refs[dyn_field] = [*refs.get(dyn_field, []), replacement]
        else:
            refs = _swap(info, removed, replacement)
        befores.append(before)
        afters.append(with_status(rule_view(info, refs), "modified", before))
    ids = [i.rule.id for i in infos]
    best_rule = max(infos, key=lambda i: i.rule.hit_count or 0)
    return Draft(
        kind="use_dynamic_object",
        principle="large_lists_belong_in_dynamic_objects",
        title=title,
        priority=_rule_priority(30 if match.kind == "identical" else 20, best_rule),
        display="split",
        deploy_cost=len(infos) + (1 if match.obj is None else 0),
        targets=extra_targets + [_rule_target(i) for i in infos],
        preview={
            "policy": _policy_ref(policy),
            "before": befores,
            "after": afters,
            "dynamic": dynamic,
            "affected_rules": {"total": len(ids), "sample": estate.rule_sample(ids)},
        },
        policy_fmc_id=policy.fmc_id,
        warnings=_warnings(match, tokens),
        plan=_plan(lambda pb: pb.block("dynamic_object_manual")),
    )
