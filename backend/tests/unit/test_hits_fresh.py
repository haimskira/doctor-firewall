"""Hit counts come from the FMC's cache: old counters never prove a rule dead."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.analysis.semantic import stale_hit_policies

TAKEN = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
DAY = timedelta(hours=24)


def test_counters_refreshed_long_before_the_snapshot_are_stale() -> None:
    # Found on the lab FMC: counters last refreshed six days before the pull.
    stats = {
        "hits_fetched_at": {
            "old": "2026-10-28T14:55:01Z",
            "fresh": "2026-11-04T09:30:00+00:00",
            "naive": "2026-11-04T10:00:00",
            "garbage": "not a date",
        }
    }
    assert stale_hit_policies(stats, TAKEN, DAY) == {"old", "garbage"}


def test_snapshots_without_fetch_times_keep_their_counters() -> None:
    assert stale_hit_policies({}, TAKEN, DAY) == set()
    assert stale_hit_policies({"hits_fetched_at": None}, TAKEN, DAY) == set()
