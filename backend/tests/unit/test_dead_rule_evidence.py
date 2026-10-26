"""A rule is "dead" only when its hit counters can prove it (seen on a real FMC 10.1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.analysis.semantic import _is_dead
from app.fmc.adapters import v10_1
from app.models.inventory import Rule

NOW = datetime(2026, 10, 27, tzinfo=UTC)
WINDOW = timedelta(days=90)


def _rule(**values: object) -> Rule:
    base: dict[str, object] = {
        "enabled": True,
        "hit_count": 0,
        "last_hit": None,
        "modified_at": None,
        "deployed_at": NOW - timedelta(days=200),
        "never_deployed": False,
    }
    base.update(values)
    return Rule(**base)


def test_dead_only_with_evidence() -> None:
    assert _is_dead(_rule(), NOW, WINDOW)  # deployed long ago, never hit
    assert not _is_dead(_rule(hit_count=None), NOW, WINDOW)  # no counters at all
    assert not _is_dead(_rule(never_deployed=True), NOW, WINDOW)
    assert not _is_dead(
        _rule(modified_at=NOW - timedelta(days=3)), NOW, WINDOW
    )  # counters restarted
    assert _is_dead(_rule(modified_at=NOW - timedelta(days=120)), NOW, WINDOW)
    assert _is_dead(_rule(hit_count=5, last_hit=NOW - timedelta(days=100)), NOW, WINDOW)
    assert not _is_dead(_rule(hit_count=5, last_hit=NOW - timedelta(days=10)), NOW, WINDOW)
    assert not _is_dead(_rule(enabled=False), NOW, WINDOW)


def test_real_fmc_hitcount_and_rule_timestamps() -> None:
    never = v10_1.map_hitcount(
        {
            "rule": {"id": "r1", "name": "A", "type": "AccessRule"},
            "hitCount": 0,
            "firstHitTimeStamp": " ",
            "lastHitTimeStamp": " ",
            "lastDeployedTimeStamp": " ",
        }
    )
    assert (never.deploy_known, never.deployed_at, never.last_hit) == (True, None, None)
    deployed = v10_1.map_hitcount(
        {
            "rule": {"id": "r1", "name": "A", "type": "AccessRule"},
            "hitCount": 3,
            "lastDeployedTimeStamp": "2026-10-26T18:53:51Z",
        }
    )
    assert deployed.deployed_at == "2026-10-26T18:53:51+00:00"
    old = v10_1.map_hitcount(
        {"rule": {"id": "r1", "name": "A", "type": "AccessRule"}, "hitCount": 1}
    )
    assert old.deploy_known is False  # older FMCs: no deployment evidence, old behaviour
    rule = v10_1.map_rule(
        {
            "id": "r1",
            "type": "AccessRule",
            "name": "A",
            "action": "ALLOW",
            "enabled": True,
            "metadata": {"ruleIndex": 1, "timestamp": 1793052397665},
        },
        1,
    )
    assert rule.attrs["modified_at"].startswith("2026-10-26")
