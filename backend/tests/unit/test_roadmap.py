"""The clean-up roadmap covers every recommendation kind, once, in a fixed order."""

from __future__ import annotations

from app.analysis.roadmap import PHASE_NAMES, PHASE_OF, PHASES
from app.models.recommendations import BEHAVIOR_CHANGING, RECOMMENDATION_KINDS


def test_every_kind_has_exactly_one_phase() -> None:
    kinds = [k for _, ks in PHASES for k in ks]
    assert len(kinds) == len(set(kinds))
    assert set(kinds) == set(RECOMMENDATION_KINDS)
    assert PHASE_NAMES == ("never_match", "objects", "structure", "access", "closing")


def test_only_the_access_phase_changes_traffic() -> None:
    changing = {PHASE_OF[k] for k in BEHAVIOR_CHANGING}
    assert changing == {"access"}
