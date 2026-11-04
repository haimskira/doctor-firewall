"""Collector review: overrides, hit-count fetch time and the manual NAT section (10.1 adapter)."""

from __future__ import annotations

from typing import Any

import pytest

from app.fmc.adapters import v10_1
from app.fmc.adapters.v10_1 import AdapterError

HOST = {"id": "h1", "name": "H_SITE", "type": "Host", "value": "10.0.0.1", "overridable": True}


def _override(**fields: Any) -> dict[str, Any]:
    return {
        "id": "h1",
        "name": "H_SITE",
        "type": "Host",
        "value": "10.9.9.9",
        "overrides": {
            "parent": {"id": "h1", "name": "H_SITE", "type": "Host"},
            "target": {"id": "dev-1", "type": "Device", "name": "FTD-A"},
        },
        **fields,
    }


def test_override_maps_target_and_canonical_value() -> None:
    assert v10_1.map_override("hosts", _override()) == {
        "target_id": "dev-1",
        "target_name": "FTD-A",
        "value": "10.9.9.9/32",
    }


def test_override_of_a_group_lists_its_members() -> None:
    item = _override(
        id="g1",
        type="NetworkGroup",
        value=None,
        objects=[{"id": "m1", "name": "H_B", "type": "Host"}],
        literals=[{"type": "Network", "value": "10.1.0.0/16"}],
    )
    entry = v10_1.map_override("networkgroups", item)
    assert entry is not None
    assert entry["value"] is None
    assert entry["members"] == ["10.1.0.0/16", "H_B"]


def test_override_without_target_is_ignored() -> None:
    assert v10_1.map_override("hosts", {"id": "h1", "name": "x", "type": "Host"}) is None
    assert v10_1.map_override("hosts", "garbage") is None


def test_override_resource_by_type() -> None:
    assert v10_1.override_resource("Host") == "hosts"
    assert v10_1.override_resource("NetworkGroup") == "networkgroups"
    assert v10_1.override_resource("SecurityZone") is None


def test_object_stays_overridable_flag_only() -> None:
    rec = v10_1.map_object("hosts", HOST)
    assert rec.attrs["overridable"] is True
    assert "overrides" not in rec.attrs


def _hit(**fields: Any) -> dict[str, Any]:
    return {"hitCount": 3, "rule": {"id": "r1", "name": "x", "type": "AccessRule"}, **fields}


def test_hitcount_fetch_time() -> None:
    hit = v10_1.map_hitcount(_hit(lastFetchTimeStamp="2026-10-28T14:55:01Z"))
    assert hit.fetched_at == "2026-10-28T14:55:01+00:00"
    assert v10_1.map_hitcount(_hit()).fetched_at is None
    assert v10_1.map_hitcount(_hit(lastFetchTimeStamp=" ")).fetched_at is None
    assert v10_1.map_hitcount(_hit(lastFetchTimeStamp="not a date")).fetched_at is None


def _manual(**fields: Any) -> dict[str, Any]:
    return {"id": "n1", "natType": "STATIC", **fields}


def test_manual_nat_section_prefers_metadata_then_top_level() -> None:
    def section(**fields: Any) -> str:
        return v10_1.map_nat_rule(_manual(**fields), 1, "MANUAL").section

    assert section(metadata={"section": "AFTER_AUTO"}) == "AFTER_AUTO"
    assert section(metadata={"section": "AFTER_AUTO"}, section="BEFORE_AUTO") == "AFTER_AUTO"
    assert section(section="AFTER_AUTO") == "AFTER_AUTO"
    assert section(metadata={"other": 1}, section="AFTER_AUTO") == "AFTER_AUTO"
    assert section() == "BEFORE_AUTO"
    assert section(metadata={}) == "BEFORE_AUTO"


def test_manual_nat_section_is_validated() -> None:
    with pytest.raises(AdapterError):
        v10_1.map_nat_rule(_manual(metadata={"section": "NOWHERE"}), 1, "MANUAL")
    with pytest.raises(AdapterError):
        v10_1.map_nat_rule(_manual(section="NOWHERE"), 1, "MANUAL")
