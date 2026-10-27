"""Group compaction: covered members go, consecutive ones merge, the addresses stay the same."""

from __future__ import annotations

from typing import cast

from app.analysis.compact import (
    _block_value,
    _drop_covered,
    _intervals,
    _Member,
    _member,
    _merge_blocks,
)
from app.analysis.expand import Leaves
from app.analysis.recommend import Estate, Obj, Ref
from app.analysis.space import AddressSet


class _Estate:
    """Just what ``_member`` reads: address objects by id and the leaves of nested groups."""

    def __init__(self, objects: dict[str, tuple[str, str]], nested: dict[str, list[str]]) -> None:
        self.objects = {
            oid: Obj(oid, oid, kind, value, False) for oid, (kind, value) in objects.items()
        }
        for gid in nested:
            self.objects[gid] = Obj(gid, gid, "network_group", None, False)
        self.resolver = self
        self._nested = nested

    def leaves(self, oid: str) -> Leaves:
        out = Leaves()
        out.addresses |= set(self._nested.get(oid, []))
        return out


def _members(estate: _Estate, ids: list[str]) -> list[_Member]:
    return [_member(cast(Estate, estate), Ref(i, i)) for i in ids]


def _union(members: list[_Member]) -> AddressSet:
    return AddressSet.build(
        [_block_value(version, lo, hi)[1] for m in members for version, lo, hi in m.intervals]
    )


def test_covered_members_go_smallest_first_and_duplicates_keep_one() -> None:
    estate = _Estate(
        {
            "net": ("network", "10.0.0.0/24"),
            "h1": ("host", "10.0.0.5/32"),
            "h1b": ("host", "10.0.0.5/32"),  # the same value twice: both are inside the /24
            "out": ("host", "10.9.9.9/32"),
            "nested_only": ("host", "10.5.0.1/32"),
        },
        {"grp": ["10.5.0.0/16"]},
    )
    members = _members(estate, ["net", "h1", "h1b", "out", "nested_only", "grp"])
    removed = {m.ref.name for m in _drop_covered(members)}
    # The hosts inside the /24 and inside the nested group go; the /24, the outsider and the
    # nested group (never a candidate) stay.
    assert removed == {"h1", "h1b", "nested_only"}
    kept = [m for m in members if m.ref.name not in removed]
    assert _union(kept) == _union(members)


def test_two_identical_members_keep_exactly_one() -> None:
    estate = _Estate({"a": ("host", "10.1.1.1/32"), "b": ("host", "10.1.1.1/32")}, {})
    members = _members(estate, ["a", "b"])
    assert len(_drop_covered(members)) == 1


def test_consecutive_members_merge_into_one_exact_value() -> None:
    estate = _Estate(
        {
            "h1": ("host", "10.70.1.1/32"),
            "h2": ("host", "10.70.1.2/32"),
            "h3": ("host", "10.70.1.3/32"),
            "h4": ("host", "10.70.1.4/32"),
            "lo": ("network", "10.70.2.0/25"),
            "hi": ("network", "10.70.2.128/25"),
            "r": ("range", "10.80.0.1-10.80.0.9"),
            "alone": ("host", "10.90.0.1/32"),
            "v6a": ("network", "2001:db8::/65"),
            "v6b": ("network", "2001:db8::8000:0:0:0/65"),
        },
        {},
    )
    blocks = _merge_blocks(_members(estate, list(estate.objects)))
    values = {value: sorted(m.ref.name for m in ms) for value, ms in blocks}
    assert values == {
        ("range", "10.70.1.1-10.70.1.4"): ["h1", "h2", "h3", "h4"],
        ("network", "10.70.2.0/24"): ["hi", "lo"],
        ("range", "10.80.0.1-10.80.0.9"): ["r"],
        ("host", "10.90.0.1/32"): ["alone"],
        ("network", "2001:db8::/64"): ["v6a", "v6b"],
    }


def _value(text: str) -> tuple[str, str]:
    version, lo, hi = _intervals([text])[0]
    return _block_value(version, lo, hi)


def test_block_values() -> None:
    assert _value("10.0.0.7/32") == ("host", "10.0.0.7/32")
    assert _value("10.0.0.0/23") == ("network", "10.0.0.0/23")
    assert _value("10.0.0.1-10.0.0.2") == ("range", "10.0.0.1-10.0.0.2")
    # Four addresses not on a /30 boundary: a range, never a wider network.
    assert _value("10.0.0.2-10.0.0.5") == ("range", "10.0.0.2-10.0.0.5")
    assert _value("2001:db8::1/128") == ("host", "2001:db8::1/128")
