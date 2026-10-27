"""After-deploy watch: when do new hits on a block rule behind a change raise an alert?"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.enforce.watch import judge

T0 = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def _rule(name: str, role: str = "block_behind", snapshot_hits: int | None = 0) -> dict[str, Any]:
    return {
        "policy": "p",
        "id": name,
        "name": name,
        "index": 1,
        "role": role,
        "snapshot_hits": snapshot_hits,
    }


def _judge(
    rules: list[dict[str, Any]], baseline: dict[str, int], hits: dict[str, int]
) -> list[str]:
    alerts = judge(
        rules,
        snapshot_at=T0 - timedelta(hours=10),
        baseline_at=T0,
        baseline=baseline,
        now=T0 + timedelta(hours=1),
        hits=hits,
        min_hits=10,
        ratio=3.0,
    )
    return [a["name"] for a in alerts]


def test_a_quiet_block_that_starts_firing_alerts() -> None:
    assert _judge([_rule("deny")], {"p/deny": 0}, {"p/deny": 50}) == ["deny"]


def test_a_block_firing_at_its_usual_rate_does_not() -> None:
    # 1 000 hits in the 10 hours before the deployment: ~100 per hour is expected.
    rule = _rule("deny", snapshot_hits=0)
    assert _judge([rule], {"p/deny": 1000}, {"p/deny": 1250}) == []
    assert _judge([rule], {"p/deny": 1000}, {"p/deny": 1400}) == ["deny"]


def test_few_new_hits_and_changed_rules_never_alert() -> None:
    assert _judge([_rule("deny")], {"p/deny": 0}, {"p/deny": 9}) == []
    assert _judge([_rule("app", role="changed")], {"p/app": 0}, {"p/app": 10_000}) == []


def test_a_reset_counter_counts_from_zero_and_missing_reads_are_skipped() -> None:
    # The counter went down (reboot): its value is all new.
    assert _judge([_rule("deny", snapshot_hits=None)], {"p/deny": 500}, {"p/deny": 40}) == ["deny"]
    assert _judge([_rule("deny")], {"p/deny": 0}, {}) == []
