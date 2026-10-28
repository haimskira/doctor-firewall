"""What the API documents about the system: every finding kind, every recommendation kind and
the areas of the API (rendered into the OpenAPI description and tag descriptions)."""

from __future__ import annotations

from app.analysis.roadmap import PHASE_OF
from app.models.recommendations import BEHAVIOR_CHANGING, RECOMMENDATION_KINDS

FINDINGS: dict[str, str] = {
    "shadowed_rule": "An earlier rule matches all of this rule's traffic: it can never match.",
    "identical_rules": "Two rules match the same traffic with the same verdict.",
    "overlap_conflict": "Two overlapping rules decide part of the same traffic differently.",
    "dead_rule": "A permit rule without hits in the dead-rule window (90 days by default).",
    "disabled_rule": "A disabled rule: it matches nothing but stays in the policy.",
    "ace_heavy_rule": "A rule that expands to more than 1 000 access-list entries.",
    "ace_cluster_limit": "A cluster near (over 80 %) or over its ACE limit.",
    "duplicate_object": "Objects of one kind holding the same value under several names.",
    "duplicate_membership": "A group holds a member directly and again through a nested group.",
    "deep_nesting": "Groups nested deeper than is maintainable.",
    "group_cycle": "A group that contains itself through its members.",
    "inline_literal": "Addresses or ports typed into rules instead of objects.",
    "unused_object": "An object no rule, group, route or interface uses.",
}

RECOMMENDATIONS: dict[str, str] = {
    "remove_disabled_rule": "Delete a disabled rule.",
    "remove_shadowed_rule": "Delete a rule an earlier rule fully covers.",
    "remove_dead_rule": "Delete a permit rule without hits.",
    "merge_duplicate_objects": "Keep one of several objects with the same value; repoint users.",
    "merge_groups": "Keep one of several groups with the same members; repoint users.",
    "remove_redundant_reference": "Drop a rule reference already inside another referenced group.",
    "remove_redundant_member": "Drop a group member already reachable through a nested group.",
    "compact_group": "Same addresses / ports with fewer group members (fewer ACEs).",
    "literal_to_object": "Replace an inline value in rules with an (existing or new) object.",
    "rename_role": "Name an address-named group after the system / tier it serves.",
    "rename_convention": "Rename an object or rule to the naming convention.",
    "split_group": "One group per destination tier.",
    "split_rule": "One rule per destination tier.",
    "merge_rules": "Merge adjacent rules that differ only by their sources.",
    "tighten_source": "Replace an any source behind zones with the networks behind them.",
    "tighten_ports": "Open only the ports the destination assets declare.",
    "add_inspection": "Attach the IPS / file policy the destination tier requires.",
    "ssl_exempt_core": "Exempt CORE services from decryption.",
    "ssl_decrypt_inbound": "Decrypt inbound traffic to servers with known keys.",
    "remove_unused_object": "Delete an object nothing uses.",
}

TAGS: list[dict[str, str]] = [
    {
        "name": "inventory",
        "description": "FMC snapshots: policies, rules, objects, clusters, routing, findings.",
    },
    {
        "name": "recommendations",
        "description": "Proposed fixes with their plan, before / after and impact; decisions.",
    },
    {
        "name": "roadmap",
        "description": "The clean-up roadmap: preparation checks and the five phases.",
    },
    {"name": "map", "description": "The connectivity map between asset systems, by risk."},
    {
        "name": "attack-surface",
        "description": "Paths to a system, blast radius of a source (up to 4 hops).",
    },
    {"name": "dashboard", "description": "The snapshot (or one policy) at a glance."},
    {
        "name": "changesets",
        "description": "Staged changes, their batches, traffic proofs, approval and runs.",
    },
    {
        "name": "history",
        "description": "Every deployed batch, before / after, after-deploy watch, revert.",
    },
    {"name": "jobs", "description": "Background jobs and their progress."},
    {"name": "assets", "description": "The asset table (systems and tiers) and cluster limits."},
    {
        "name": "relations",
        "description": "Object relations: where an object is used, and redundancies.",
    },
    {"name": "audit", "description": "The hash-chained audit log (audit:read)."},
    {"name": "fmc", "description": "FMC connections (administrators)."},
    {"name": "users", "description": "Local users and roles (administrators)."},
    {"name": "auth", "description": "Sign-in and the session."},
    {"name": "developer", "description": "API tokens and this document."},
    {"name": "health", "description": "Liveness and readiness."},
]


def description() -> str:
    """The OpenAPI document's description: how to use the API, and what the system finds."""
    findings = "\n".join(f"| `{k}` | {v} |" for k, v in FINDINGS.items())
    recs = "\n".join(
        f"| `{k}` | {RECOMMENDATIONS.get(k, '')} | {PHASE_OF.get(k, '')} | "
        f"{'changes access' if k in BEHAVIOR_CHANGING else 'no traffic change'} |"
        for k in RECOMMENDATION_KINDS
    )
    return f"""Doctor Firewall analyses Cisco Secure Firewall (FMC / FTD) policies, proposes proven
fixes and applies them only after a second person approves, in batches under the deploy limit,
with a traffic proof before and after writing, an after-deploy watch and an exact revert.

**Authentication.** A signed-in browser session (cookie; writes also send `X-CSRF-Token`), or
`Authorization: Bearer <token>` with a token from *Integrations → API for developers*. Tokens
are **read-only** (GET / HEAD, the owner's read permissions): changes to the firewall go through
the UI and its four-eyes approval.

**Conventions.** JSON over HTTPS. Lists take `limit` (≤ 500) and `offset` and answer `total`;
many take `sort` and `order`. A `policy` parameter narrows insight views to one access policy's
world: its rules, its devices and the objects its rules use (directly or through groups).
Errors: HTTP status with `{{"detail": "<code>"}}`.

### Findings

| kind | meaning |
|---|---|
{findings}

### Recommendations

| kind | proposal | roadmap phase | traffic |
|---|---|---|---|
{recs}
"""
