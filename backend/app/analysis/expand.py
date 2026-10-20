"""Resolve objects and groups to concrete leaves, and build each rule's match space.

ACE expansion is never stored; it is derived here, per analysis run, from the object
graph — exactly what the FMC does when it flattens groups into Lina ACEs.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from math import prod

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.space import AddressSet, MatchSpace, PortSet, TokenSet
from app.fmc.records import ObjectKind
from app.models.inventory import FwObject, GroupMember, Rule, RuleRef

_ADDRESS_KINDS = {ObjectKind.HOST.value, ObjectKind.NETWORK.value, ObjectKind.RANGE.value}
_PORT_KINDS = {ObjectKind.PORT.value, ObjectKind.ICMP.value}
_GROUP_KINDS = {
    ObjectKind.NETWORK_GROUP.value,
    ObjectKind.PORT_GROUP.value,
    ObjectKind.URL_GROUP.value,
}


@dataclass
class Leaves:
    addresses: set[str] = field(default_factory=set)  # canonical CIDR / range strings
    address_tokens: set[str] = field(default_factory=set)  # FQDNs, unresolvable objects
    ports: set[str] = field(default_factory=set)  # canonical PROTO/ports specs
    tokens: set[str] = field(default_factory=set)  # zones, apps, SGTs, URLs, ...

    def update(self, other: Leaves) -> None:
        self.addresses |= other.addresses
        self.address_tokens |= other.address_tokens
        self.ports |= other.ports
        self.tokens |= other.tokens

    def count(self) -> int:
        return len(self.addresses) + len(self.address_tokens) + len(self.ports) + len(self.tokens)


def literal_leaves(literal: str, kind: str | None) -> Leaves:
    leaves = Leaves()
    if kind in ("address", "range"):
        leaves.addresses.add(literal)
    elif kind in ("port", "icmp"):
        leaves.ports.add(literal)
    else:
        leaves.tokens.add(f"{kind or 'literal'}:{literal}")
    return leaves


class Resolver:
    """Object id -> Leaves, memoised and safe against group cycles."""

    def __init__(
        self,
        objects: dict[str, tuple[str, str | None]],
        members: dict[str, list[tuple[str | None, str | None, str | None]]],
    ) -> None:
        self._objects = objects
        self._members = members
        self._cache: dict[str, Leaves] = {}

    @staticmethod
    def load(session: Session, snapshot_id: int) -> Resolver:
        objects = {
            fid: (kind, value)
            for fid, kind, value in session.execute(
                select(FwObject.fmc_id, FwObject.kind, FwObject.value).where(
                    FwObject.snapshot_id == snapshot_id
                )
            ).all()
        }
        members: dict[str, list[tuple[str | None, str | None, str | None]]] = defaultdict(list)
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
            members[group].append((member, literal, literal_kind))
        return Resolver(objects, dict(members))

    def leaves(self, object_id: str) -> Leaves:
        if object_id in self._cache:
            return self._cache[object_id]
        result = Leaves()
        # Iterative DFS with a per-root visited set: cycles contribute their leaves once.
        stack = [object_id]
        seen: set[str] = set()
        while stack:
            oid = stack.pop()
            if oid in seen:
                continue
            seen.add(oid)
            kind, value = self._objects.get(oid, (ObjectKind.OTHER.value, None))
            if kind in _GROUP_KINDS:
                for member, literal, literal_kind in self._members.get(oid, []):
                    if member is not None:
                        stack.append(member)
                    elif literal is not None:
                        result.update(literal_leaves(literal, literal_kind))
            elif kind in _ADDRESS_KINDS and value:
                result.addresses.add(value)
            elif kind == ObjectKind.FQDN.value:
                result.address_tokens.add(f"fqdn:{value or oid}")
            elif kind in _ADDRESS_KINDS:
                result.address_tokens.add(oid)  # stub without a value
            elif kind in _PORT_KINDS and value:
                result.ports.add(value)
            else:
                result.tokens.add(oid)
        self._cache[object_id] = result
        return result


@dataclass(frozen=True)
class RuleSpace:
    rule_id: int
    fmc_id: str
    policy_fmc_id: str
    rule_index: int
    section: str
    name: str
    enabled: bool
    action: str
    hit_count: int | None
    space: MatchSpace
    ace_count: int
    leaf_counts: dict[str, int]


_SPACE_FIELDS = (
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
# Fields that multiply into Lina ACEs (applications, URLs, users... are Snort-side).
ACE_FIELDS = ("src_zone", "dst_zone", "src_net", "dst_net", "src_port", "dst_port")


def build_space(field_leaves: dict[str, Leaves]) -> MatchSpace:
    def addresses(name: str) -> AddressSet:
        leaves = field_leaves.get(name)
        if leaves is None:
            return AddressSet(any=True)
        return AddressSet.build(leaves.addresses, leaves.address_tokens | leaves.tokens)

    def ports(name: str) -> PortSet:
        leaves = field_leaves.get(name)
        if leaves is None:
            return PortSet(any=True)
        built = PortSet.build(leaves.ports)
        extra = leaves.tokens | leaves.address_tokens
        return PortSet(
            any=built.any, by_protocol=built.by_protocol, tokens=built.tokens | frozenset(extra)
        )

    tokens = []
    for dim in (
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
    ):
        leaves = field_leaves.get(dim)
        if leaves is not None:
            tokens.append(
                (
                    dim,
                    TokenSet.build(
                        leaves.tokens | leaves.address_tokens | leaves.addresses | leaves.ports
                    ),
                )
            )
    return MatchSpace(
        src_net=addresses("src_net"),
        dst_net=addresses("dst_net"),
        src_port=ports("src_port"),
        dst_port=ports("dst_port"),
        tokens=tuple(tokens),
    )


def ace_estimate(field_leaves: dict[str, Leaves]) -> int:
    """Lina ACE estimate: product of leaf counts of the multiplying fields ("any" = 1).

    Matches how the FMC flattens object groups; it is an estimate because Object Group
    Search (if enabled on the device) keeps groups unexpanded.
    """
    return prod(max(1, field_leaves[f].count()) if f in field_leaves else 1 for f in ACE_FIELDS)


def rule_spaces(
    session: Session, snapshot_id: int, policy_id: str, resolver: Resolver
) -> list[RuleSpace]:
    """All rules of a policy, in evaluation order, with their match spaces."""
    rules = session.scalars(
        select(Rule)
        .where(Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id == policy_id)
        .order_by(Rule.rule_index)
    ).all()
    refs: dict[int, dict[str, Leaves]] = defaultdict(dict)
    for rule_id, fld, oid, literal, literal_kind in session.execute(
        select(
            RuleRef.rule_id,
            RuleRef.field,
            RuleRef.object_fmc_id,
            RuleRef.literal,
            RuleRef.literal_kind,
        )
        .join(Rule, Rule.id == RuleRef.rule_id)
        .where(Rule.snapshot_id == snapshot_id, Rule.policy_fmc_id == policy_id)
    ).all():
        if fld not in _SPACE_FIELDS:
            continue
        bucket = refs[rule_id].setdefault(fld, Leaves())
        if oid is not None:
            bucket.update(resolver.leaves(oid))
        elif literal is not None:
            bucket.update(literal_leaves(literal, literal_kind))
    out = []
    for r in rules:
        fields = refs.get(r.id, {})
        out.append(
            RuleSpace(
                rule_id=r.id,
                fmc_id=r.fmc_id,
                policy_fmc_id=r.policy_fmc_id,
                rule_index=r.rule_index,
                section=r.section,
                name=r.name,
                enabled=r.enabled,
                action=r.action,
                hit_count=r.hit_count,
                space=build_space(fields),
                ace_count=ace_estimate(fields),
                leaf_counts={f: fields[f].count() for f in fields},
            )
        )
    return out
