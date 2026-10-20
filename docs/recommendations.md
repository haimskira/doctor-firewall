# Recommendations and naming convention (phase 3)

Recommendations turn findings and scores into concrete, doctrine-backed changes **on the local
copy**. Nothing is written to the FMC: an operator (role *optimizer*, permission
`changeset:write`) accepts or dismisses each recommendation; accepted recommendations are the
input of the changeset / batch / deploy flow of phase 5. Source:
`backend/app/analysis/recommend.py`, recomputed by every analysis run (after each pull, or on
demand with *Re-run analysis*, permission `collect:run`).

Every recommendation carries:

| Field | Meaning |
|---|---|
| preview | `before` / `after` rule views (each `after` row has a status — unchanged / modified / new / removed — and per-field added / removed values), and/or object cards, a rename, or a literal replacement, plus a sample of the affected rules |
| display | `inline` for point changes (tighten, remove, rename); `split` (before / after) for structural ones (split, merge) — as the spec requires; the UI lets the operator toggle |
| deploy cost | number of FMC **write operations** it implies: each object or rule create / update / delete counts 1. A rename is 1 (rules and groups reference objects by id) |
| ACE delta | estimated change in Lina ACEs (negative = saved), same estimate as phase 2 |
| score delta | expected change of the rule score (for splits / merges: mean of the new rules minus the old score) |
| warnings | what the operator must weigh before accepting (table below) |
| fingerprint | SHA-256 of the kind, the targets and the proposal, **without rule positions**. Decisions are stored by fingerprint, so they survive the next pull, and are dropped automatically when the rule / object or the proposal changes |

## Kinds

| Kind | When | Proposal | Behaviour |
|---|---|---|---|
| `remove_shadowed_rule` | an earlier rule covers all of the rule's traffic (phase 2) | delete the rule | unchanged (the rule can never match); opposite verdict → warning `conflict_intent`, higher priority |
| `remove_dead_rule` | an enabled **permit** access rule without hits in the window | delete the rule | narrows access only; deny rules are never proposed for removal (removing a deny could open traffic) |
| `split_rule` | a permit rule whose destination spans several tiers | one rule per destination tier (GOLD → SILVER → BRONZE → CORE → USERS → unclassified), the first keeps the rule's id, the others are inserted right after it | unchanged (same action, union of destinations, adjacent). Mixed groups are expanded into members (`group_expanded`); a single object spanning tiers blocks the split |
| `merge_rules` | adjacent enabled permit rules (same section / category) identical in everything but their sources | one rule with the union of sources | unchanged (adjacent, same verdict); only "same destination + service" is merged — merging destinations would break "one tier per rule" |
| `tighten_source` | a permit rule with *any* source and source zone(s) | the networks behind those zones: interface subnets + static / connected routes through the zone's interfaces on the clusters the policy governs | narrows access — verify (`derived_from_routing`). Skipped when a default route sits behind the zone or a route cannot be resolved |
| `tighten_ports` | a permit rule with any / > 100 ports toward destinations fully covered by assets that declare their ports | the declared ports (existing port objects when they exist) | narrows access — never widens, only a strict reduction; skipped when any asset has no / unclear ports |
| `merge_duplicate_objects` | objects of one kind with the same value | keep the most-referenced (then convention-compliant, then shortest name), repoint rules / groups / routes, delete the rest | unchanged |
| `merge_groups` | network / port groups resolving to the same members | as above | unchanged; groups nested in one another are skipped (self-reference) |
| `split_group` | a rule-referenced network group whose members belong to several tiers | one group per tier (convention name or `<group>_<TIER>`), references repointed, old group deleted | unchanged |
| `rename_role` | a network group named by address (`GRP_10.30.0.0`) whose members map to one system / tier | the convention name, else `GRP_<ROLE>` | label only |
| `rename_convention` | an object or access rule not matching the admin convention, when every token resolves | the computed name; collisions get `_2`, `_3`… (`name_disambiguated`) | label only |
| `literal_to_object` | an inline address / port value in rules | the existing object with that value, or a new convention-named object | unchanged |
| `remove_unused_object` | an object referenced by no collected rule, group, route or interface | delete | `external_references`: it may be used by configuration that is not collected |

Priorities (0–100, higher first): shadowed 75 (conflict 85), tighten source 55+, dead 60,
split / tighten ports 50+, split group 45, merge rules 40, merge groups 35, duplicates 30,
literals 25, role names 20, convention renames 15, unused objects 10; rule-based kinds get up to
+20 for a low current score.

### Warnings

| Code | Meaning |
|---|---|
| `conflict_intent` | a shadowing rule has the opposite verdict — removal keeps behaviour, but the intent must be checked |
| `hit_counts_reset` | hit counts reset on reboot / some deploys |
| `external_references` | names may be used outside the FMC (automation, scripts, docs) |
| `derived_from_routing` | the source set comes from interfaces and routes |
| `literal_needs_object` | some proposed values have no object yet |
| `asset_ports_declared` | ports come from the asset table |
| `group_expanded` | a mixed group was expanded into members |
| `unclassified_part` | part of the addresses is not in the asset table |
| `name_disambiguated` | a suffix was added to avoid a duplicate name |

## Naming convention

Defined per kind by an administrator (permission `conventions:manage`, admin role) — `host`,
`network`, `range`, `fqdn`, `network_group`, `port`, `port_group`, `rule` (access rules). A
template is literal text (`A-Z a-z 0-9 _ . -`) plus `<TOKEN>` placeholders, with a letter case
(UPPER / lower / as typed). Tokens must be separated by at least one character.

| Token | Kinds | Value |
|---|---|---|
| `VALUE` | host, network, range, fqdn | the object's value: `10.1.1.5`, `10.20.0.0-16`, `a-b`, the FQDN |
| `SYSTEM` | address kinds, network group | the single asset-table system covering every address |
| `TIER` | address kinds, network group, rule | the single tier covering every (destination) address |
| `TYPE` | address kinds, network group | the single asset system type |
| `ROLE` | address kinds, network group | `SYSTEM`, else `TIER` |
| `PROTO`, `PORT` | port | protocol and port (range) |
| `SVC` | port, port group, rule | one application's name, else well-known port names (SQL, SSH, HTTPS…) or `<PROTO><PORT>`, up to three joined with `-` |
| `SRC`, `DST` | rule | the system name; else `<TIER>-<TYPE>`; else the tier; for user space the user type |
| `ACTION` | rule | the rule action |

A token that cannot be resolved unambiguously (e.g. a destination spanning two systems) means
**no proposal** — the name is only reported as non-compliant. Compliance counts per kind are kept
in the snapshot (`stats.naming`) and shown on the Naming convention page. Names longer than 64
characters are not proposed (*to verify* against the FMC limits per object type).
