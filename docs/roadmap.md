# Clean-up roadmap

*Manage → Policies → Clean-up roadmap* (`/roadmap`, API `GET /api/snapshots/{id}/roadmap`) orders a
rulebase clean-up. Each phase changes what the next one sees, so a project goes phase by phase:
decide → stage → approve → deploy → **pull and analyse again** → next phase (a snapshot behind
changes cannot be staged from).

| # | Phase | Recommendations | Traffic |
|---|---|---|---|
| 0 | Preparation | checks: confirmed assets, verified cluster ACE / deploy limits, hit counters on every enabled rule (and the dead-rule window), snapshot not behind the FMC | — |
| 1 | Rules that match nothing | disabled rules, shadowed rules | no change |
| 2 | Objects and groups | merge duplicate objects / groups, redundant references / members, compact groups, inline values to objects, names | no change |
| 3 | Rule structure by tier | split groups, split rules, merge rules (after the split) | no change |
| 4 | Changes to access | dead rules, tighten source / ports, inspection, decryption | **changes** — owner approval, after-deploy watch |
| 5 | Closing | unused objects | no change |

Why this order: rules that never match distort merges, splits and ACE counts, so they go first;
merging duplicate objects makes identical rules visible as identical and gives later groups the
convention names; splitting before merging keeps one tier per rule; access changes come last, on
a clean base, one at a time; the objects left behind by phases 2–3 are removed at the end.

A phase is **done** when nothing in it is left to decide or to stage; the first phase that is not
done is **now**. The recommendations page takes `?phase=` (and the bulk decision a `phase`), and a
recommendation from a later phase shows a warning — it is not blocked.
