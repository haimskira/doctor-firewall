"""The order of a rulebase clean-up project: which recommendations come first, and why.

Each phase changes what the next one sees, so a project goes phase by phase — deploy, collect
and analyse again, then the next phase (a snapshot behind changes cannot be staged from):

0. **prepare** — asset table (tiers), verified cluster limits, hit counters with history: without
   them tier splits, deploy batches and "dead rule" are guesses.
1. **never_match** — rules that match nothing (disabled, shadowed). They distort every later
   analysis (merges, splits, ACE counts), and removing them changes no flow.
2. **objects** — objects and groups, no flow changes: merge duplicates (identical rules then show
   as identical), drop redundant references / members, compact groups, inline values to objects,
   names by the convention (the groups later steps create follow it too).
3. **structure** — split groups and rules by destination tier, then merge rules that share
   destination and service (after the split, so a merge never joins tiers again).
4. **access** — what changes access, each with the owner's approval and the after-deploy watch:
   rules without hits, tighter sources / ports, inspection by tier, decryption.
5. **closing** — objects nothing uses any more (many are left by phases 2 and 3).
"""

from __future__ import annotations

from typing import Final

PHASES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("never_match", ("remove_disabled_rule", "remove_shadowed_rule")),
    (
        "objects",
        (
            "merge_duplicate_objects",
            "merge_groups",
            "remove_redundant_reference",
            "remove_redundant_member",
            "compact_group",
            "literal_to_object",
            "rename_role",
            "rename_convention",
        ),
    ),
    ("structure", ("split_group", "split_rule", "merge_rules")),
    (
        "access",
        (
            "remove_dead_rule",
            "tighten_source",
            "tighten_ports",
            "add_inspection",
            "ssl_exempt_core",
            "ssl_decrypt_inbound",
        ),
    ),
    ("closing", ("remove_unused_object",)),
)
PHASE_NAMES: Final[tuple[str, ...]] = tuple(name for name, _ in PHASES)
PHASE_OF: Final[dict[str, str]] = {kind: name for name, kinds in PHASES for kind in kinds}


def kinds_of(phase: str) -> tuple[str, ...]:
    return dict(PHASES)[phase]
