"""Prefilter in front of an access hop: first match decides; only a full block cuts it."""

from __future__ import annotations

from app.analysis.attack import _prefilter_verdict
from app.analysis.space import AddressSet, MatchSpace


def _space(src: str) -> MatchSpace:
    return MatchSpace(src_net=AddressSet.build([src]))


HOP = _space("10.1.0.0/16")


def test_a_block_that_covers_the_hop_first_cuts_it() -> None:
    assert _prefilter_verdict([("BLOCK", _space("10.0.0.0/8"))], HOP) == (True, False)


def test_a_block_over_part_of_the_hop_marks_it() -> None:
    assert _prefilter_verdict([("BLOCK", _space("10.1.0.0/24"))], HOP) == (False, True)


def test_an_earlier_fastpath_or_analyze_keeps_the_hop() -> None:
    rules = [("ANALYZE", _space("10.1.0.0/17")), ("BLOCK", _space("10.0.0.0/8"))]
    # Part of the traffic is analysed (goes on to the access policy): blocked only in part.
    assert _prefilter_verdict(rules, HOP) == (False, True)
    covering_fastpath = [("FASTPATH", _space("10.0.0.0/8")), ("BLOCK", _space("10.0.0.0/8"))]
    assert _prefilter_verdict(covering_fastpath, HOP) == (False, False)


def test_rules_that_do_not_meet_the_hop_change_nothing() -> None:
    assert _prefilter_verdict([("BLOCK", _space("192.168.0.0/16"))], HOP) == (False, False)
