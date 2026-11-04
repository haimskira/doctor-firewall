"""Unit regressions found in review: route lookup over odd networks, periodic job expiry,
the throttle's failure count, PATCH nulls and the CSV reader."""

from __future__ import annotations

from datetime import timedelta

import fakeredis
import pytest
from pydantic import ValidationError

from app.analysis import routing
from app.api.assets import AssetPatch, GroupPatch, _parse_csv, _safe_cell, _unescape_cell
from app.auth.throttle import LoginThrottle
from app.workers.queues import QueueName, get_queue
from app.workers.scheduler import Schedule, run_due


def _route(network: str, kind: str = "static", distance: int = 1) -> routing.Candidate:
    return routing.Candidate(
        kind=kind,
        protocol=kind,
        network=network,
        interface="inside",
        gateway=None,
        distance=distance,
    )


def test_route_lookup_skips_networks_that_are_not_prefixes() -> None:
    candidates = [
        _route("10.0.0.1-10.0.0.9"),  # a range network object
        _route("fmc.example.com"),  # an FQDN object
        _route("2001:db8::/32"),
        _route("10.0.0.5/8"),  # host bits set: still the 10/8 prefix
        _route("10.0.0.0/24", kind="connected", distance=0),
        _route("0.0.0.0/0", distance=10),
    ]
    found = routing.lookup("10.0.0.7", candidates)
    assert [c.network for c in found] == ["10.0.0.0/24", "10.0.0.5/8", "0.0.0.0/0"]
    assert routing.lookup("192.168.1.1", [_route("a-b"), _route("fqdn")]) == []


def _noop() -> None:
    return None


def test_periodic_jobs_expire_when_not_started_in_their_interval() -> None:
    redis = fakeredis.FakeRedis()
    schedules = (Schedule("noop", _noop, QueueName.MAINTENANCE, 60),)
    assert run_due(redis, 1000.0, schedules) == ["noop"]
    job = get_queue(QueueName.MAINTENANCE, redis).jobs[0]
    assert job.ttl == 60


def test_throttle_reports_the_users_failure_count() -> None:
    throttle = LoginThrottle(fakeredis.FakeRedis(), max_failures=3, lockout=timedelta(minutes=5))
    assert throttle.max_failures == 3
    assert throttle.register_failure("Alice", "10.0.0.1") == 1
    assert throttle.register_failure("alice", "10.0.0.2") == 2


@pytest.mark.parametrize("field", ["system", "tier", "system_type", "ports", "notes", "confirmed"])
def test_asset_patch_null_is_refused_for_required_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        AssetPatch.model_validate({field: None})


def test_patch_null_stays_meaningful_where_the_column_is_nullable() -> None:
    patch = AssetPatch.model_validate({"group_id": None, "user_type": None})
    assert patch.model_dump(exclude_unset=True) == {"group_id": None, "user_type": None}
    assert GroupPatch.model_validate({"user_type": None}).user_type is None
    with pytest.raises(ValidationError):
        GroupPatch.model_validate({"name": None})


def test_csv_reader_handles_semicolons_and_header_case() -> None:
    parsed = _parse_csv("Network ; SYSTEM;tier\n10.0.0.0/8;A;GOLD\n")
    assert parsed == (["network", "system", "tier"], [["10.0.0.0/8", "A", "GOLD"]])
    parsed = _parse_csv('network,system,tier\n10.0.0.0/8,"A;B",GOLD\n')
    assert parsed == (["network", "system", "tier"], [["10.0.0.0/8", "A;B", "GOLD"]])
    assert _parse_csv("") is None


@pytest.mark.parametrize("value", ["=1+1", "+1", "-x", "@SUM", "plain", "'quoted", "\tTab"])
def test_formula_escape_round_trips(value: str) -> None:
    assert _unescape_cell(_safe_cell(value)) == value
