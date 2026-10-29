# Plan v2 — terminology, sortable tables, readable findings, attack surface

Tracked implementation plan for the requests of 2026-10-27. Each stage ships with tests, passes
CI and is pushed before the next starts. Status: `[ ]` open · `[~]` in progress · `[x]` done.

## Stage 1 — Hebrew terminology `[x]`

An access / prefilter policy is a **חוקה** in the Hebrew UI.

- [x] "מדיניות" → "חוקה" where it means the access/prefilter rulebase (nav, policy list, rule
      table column, dashboard tile, clusters page, back links).
- [x] "עורך מדיניות" → "עורך החוקה"; "מדיניות אבטחה" → "חוקות".
- [x] IPS policy, file policy, password policy keep "מדיניות" (they are not rulebases).
- [x] Tests updated; `docs/ui-design.md` glossary.

## Stage 2 — Readable findings `[x]`

Today a finding expands to its raw JSON (e.g. `ace_cluster_limit` shows a cluster UUID). Every
finding kind gets a plain-language view instead:

- [x] One renderer per kind: what was found, why it matters, where it comes from, what to do —
      names (never internal ids), links to the rule in the policy editor / the object in the
      explorer, numbers formatted.
- [x] `ace_cluster_limit`: "FTDv-Cluster uses 896,315 of 1,000,000 access-list entries (90 %)"
      with a gauge; explains that ACEs are the system's expansion of the rules (sources ×
      destinations × services) and that the limit is the configured value for the platform
      (marked *unverified* until set per cluster under Settings).
- [x] Raw JSON removed from the page; headlines localised; route and group details carry names
      (cluster, group) instead of ids. Tests.

## Stage 3 — Sortable tables `[x]`

- [x] Shared `SortableHeader` + `useSort` (click toggles descending ↔ ascending, `aria-sort`,
      keyboard, numbers / dates / text compared correctly, Hebrew collation).
- [x] Tables loaded whole sort in the browser: assets, clusters, FMC connections, inspection,
      naming, users, snapshots, deploy, dashboard, object detail.
- [x] Paged tables sort on the server (`sort` / `order` query parameters, whitelisted columns,
      parameterised SQL): objects (incl. rule / group counts), findings, recommendations,
      scores (audit pages by time on the server and sorts the loaded rows).
- [x] The policy editor stays in evaluation order: the first match decides, so a sorted
      rulebase would misrepresent the policy (its search still filters).

## Stage 4 — Attack surface and blast radius `[x]`

Pick a target and see every way the policy lets traffic reach it, hop by hop, with the ports and
applications of each hop; or pick a compromised source and see everything it can reach.

### Semantics

- A **hop** is a flow an effective permit rule allows: enabled ALLOW / TRUST access rule (and
  prefilter FASTPATH), restricted to the part not taken by earlier rules (first match). Services,
  applications, zones and the policy / cluster are kept per hop.
- **Pivoting**: `C → B → A` is a path only when the addresses of B that C may reach overlap the
  addresses of B allowed to reach A (address-level, not just "same system").
- Sources that are `any` are shown as **Anywhere** (incl. the internet); unclassified addresses
  as their networks. Nodes are grouped by the asset table (tier / system) and can be opened down
  to networks.
- Traffic inside one segment never crosses the firewall: shown as a note, not as a path.
- Depth: up to 4 hops (default 3); results ranked by risk — entry from Anywhere / users / BRONZE,
  shortest paths, tier skips, missing IPS first.

### Work

- [x] **Engine** (`app/analysis/attack.py`): reachability index per snapshot from rule leaves
      (address sets, services, apps, zones, effective space); reverse search to a target, forward
      search from a source; path enumeration with pivot checks, caps and ranking. Unit tests
      incl. the `C → B → A` example and first-match cases.
- [x] **API**: `GET /snapshots/{sid}/attack-surface?system=|object=|address=&mode=to|from&depth=&cluster=`
      (+ `/targets`); validated input, RBAC policy:read, response limits.
- [x] **UI** "משטח תקיפה" (Monitor): target search, mode (paths to / blast radius from), depth;
      radial layout with the target in the centre and rings by hop distance, edges coloured by
      risk and labelled with services; side panel with ranked paths, each hop's rules linking to
      the policy editor; summary (entry points, exposure from Anywhere, shortest path, exposed
      services). Dark mode, RTL, same design language as the connectivity map.
- [x] **Docs** `docs/attack-surface.md`; integration test against the mock; checked on the lab
      snapshot (3 000 rules: ~3 s to load the rules once per snapshot, then ~0.2 s per query).

## Stage 5 — Job status with live progress `[x]`

Every background job — FMC pull, analysis, batch write + deploy, finishing a rollback, audit-chain
check, scheduled pulls — is visible with its progress, without refreshing, and says when it ends.

- [x] **Job record** (`job_runs`): kind, subject (snapshot / batch), title, requested by, status
      (queued / running / done / failed), progress 0–100 %, current step, started / finished,
      error (scrubbed). Created when the job is queued; updated by the worker at each step.
- [x] **Progress from the work itself**: pull — resources and policies collected out of the total;
      analysis — policies analysed and recommendation steps; batch — operations written, then
      verification and deployment (FMC task state); rollback — steps undone.
- [x] **Lost workers**: a job still "running" whose worker is gone is marked failed, not left
      spinning.
- [x] **API**: `GET /api/jobs` (active + recent, filter by kind / status), RBAC on what the job
      touches (audit-chain jobs only for audit readers).
- [x] **UI**: a jobs indicator in the top bar (running count, progress bars, elapsed time) that
      updates itself every 2 s while something runs; a notice when a job ends, with a link to
      its result; a full *Jobs* page (history, sortable); inline progress where a job is started
      (pulls, re-analysis, batch run).
- [x] Tests (worker progress, lost-worker reconciliation, API, UI), docs.

## Stage 6 — Traffic guarantee, history and rollback to any point `[x]`

The system may only improve the policy, never hurt production traffic.

- [x] **6a Behaviour class**: every recommendation is *preserves* (no flow's verdict changes) or
      *changes* (less access, more inspection, removing a rule without hits). Bulk accept without a
      type filter takes only *preserves*; a *changes* type needs an explicit acknowledgement.
- [x] **6b Traffic proof per batch**: build the rulebase as it will be after the batch (plan applied
      to the snapshot model) and run probe flows — generated from the boundaries of every rule the
      batch touches and of the rules overlapping them — through both, first match. Any flow whose
      verdict or inspection changes is listed. At staging (report per batch), before running (a
      *preserves* batch with a difference is refused) and after deployment (the same proof on what
      the FMC actually holds, read back).
- [x] **6c History and rollback**: every batch with its before / after per rule and object (journal
      pre-images + read-back after-images), readable diffs; revert a deployed batch (refused if the
      FMC changed since), revert to any point (later batches first); snapshots behind changes are
      never deleted, so the previous policy is always there.
- [x] **6d After deployment**: hit counters of touched rules and of the block rules behind them
      compared with before; an alert with a one-click revert when blocked traffic appears.
- [ ] **6e Device check** (if the FMC API allows it — verify in the lab): packet-tracer on the FTD for
      critical flows before / after deployment. *Deferred 2026-10-27*: the API works, but the lab FTDv
      has no real network (every flow drops with no-route), so it cannot be validated there.

## Stage 7 — Operator feedback round 2 (easiest first) `[x]`

- [x] **7.1 Terminology**: no "אצווה" anywhere — a changeset is cut into numbered changesets
      ("changeset 3.2"), the user's choice of 2026-10-27.
- [x] **7.2 Recommendations toolbar**: buttons aligned, one size, wrapping cleanly; the bulk buttons
      read short ("אישור הכול" / "החזרה לפתוחות") with the type in the confirmation.
- [x] **7.3 Staging that just works**: staging takes the accepted recommendations that are not in
      an open changeset (and says how many were left out and where); "already in an open
      changeset" errors name the changeset with a link; cancelling a changeset is offered right
      there and on the deploy page.
- [x] **7.4 Findings lead to a fix**: every finding offers its fix — the recommendations for that
      rule / object, or why there is none yet; the dashboard's "top findings" open the fixes.
- [x] **7.5 Disabled rules**: a finding and a recommendation to remove disabled rules (preserving —
      they match nothing; the traffic proof shows it), listed by age when known.
- [x] **7.6 SGT and dynamic objects**: shown in the rule editor and object explorer; dynamic objects'
      address mappings collected (FMC `dynamicobjects/{id}/mappings`) so analysis, the map and the
      attack surface use real addresses; rules conditioned on SGT / dynamic objects marked as such
      in the attack surface; mock + tests (the lab FMC has ISE disabled: no SGTs there).
      *Decided 2026-10-27*: the mappings are shown, but analysis keeps the object as an opaque
      condition (an orchestrator changes them without a deploy).
- [x] **7.7 ACE-heavy rules get a fix**: a new preserving recommendation that replaces long address
      lists by the fewest networks covering exactly the same addresses (a summarised group), proved
      by the traffic proof; plus advice on Object Group Search where the platform supports it.
      Done as `compact_group` (covered members dropped, touching ones merged; lab snapshot 24:
      107 groups, heavy rules ~470k -> ~5k ACEs).

## Stage 8 — Round 3 (2026-10-27) `[x]`

- [x] **8.1 Bell and ACE-limit findings**: the bell counts high + medium findings and opens them
      unfiltered; the cluster ACE-limit finding lists the recommendations that save the most.
- [x] **8.2 Clean-up roadmap** (`docs/roadmap.md`): preparation checks and five phases in order,
      a phase filter on recommendations and bulk decisions, a warning on later-phase items.
- [x] **8.3 Port groups compacted** like network groups (per protocol).
- [x] **8.4 Attack surface**: prefilter blocks cut / mark hops; zones narrow hops to the networks
      routed behind them.
- [x] **8.5 Base image** `python:3.12.16-slim-bookworm` (libssl3 deb12u2, CVE-2026-84782 fixed).

## Stage 9 — Before production (requested 2026-10-28) `[ ]`

Open from stage 8 first: commit + push the test_proof fix (CI alone), then publish 0.7.0 to
Docker Hub (approved by the user; Trivy must pass on api / web / postgres / redis).

- [ ] **9.1 System guide (HTML)**, in the style of `firewall-policy-system-spec.html`: the whole
      system for the simple user (LLD level) — every screen, button and the way of working
      (roadmap phases, decide / stage / approve / deploy / watch / revert), with screenshots;
      deployment in Docker (online + offline bundle), resources, configuration; troubleshooting
      and debugging; supported FMC / FTD versions, limitations and working conditions.
- [ ] **9.2 Dry run from zero** (lab, before customers): wipe the system's data as on a fresh
      install; delete every policy in the lab FMC and create 4 main access policies, each with
      2 000 messy rules (duplicates, shadowed, disabled, wide, tier-mixing, literals ...) and
      2 000 new objects (duplicates, redundant / nested / consecutive members, bad names ...) —
      the most problematic firewall possible, covering every kind the system fixes; then take it
      through the whole roadmap from phase 0 and verify each kind of change end to end.

- [x] **9.3 Public API with an explorer** (`docs/api.md`; done 2026-10-28) (requested 2026-10-28): a new `api-docs` page (sign-in
      required) with an interactive API explorer, so developers and other systems can pull all of
      the system's data; it documents every finding kind and every capability. Needs: tokens for
      systems (service accounts / API keys, read scopes) beside the browser session, a stable
      versioned read API, OpenAPI served only to signed-in users, the explorer bundled offline
      (no CDN).

- [x] **9.4 Sign-in page** laid out like the FMC's (own mark and an original night-city backdrop — no vendor assets).
- [x] **9.5 Unassigned access policies** are collected and analysed (staging), not on the map or in the attack surface unless that policy is chosen (found by the dry run).
- [x] **9.6 Swagger UI** beside the explorer (every operation, offline bundle) (requested 2026-10-28).
- [x] **9.7 One policy at a time** on every insight page (dashboard, map, attack surface, findings, scores,
      recommendations, roadmap); the rule editor shows a policy's own devices only (an unassigned policy
      under no cluster) and lists every access policy (requested 2026-10-28).
- [x] **9.8 A policy is a world of its own** (requested 2026-10-29): every finding and recommendation
      carries the access policies it belongs to (`policy_ids`, `app/analysis/policy_scope.py`): rule
      items their policy (prefilter / decryption rules the access policies linking them), object items
      every policy whose rules use the object directly or through groups, cluster items the policies
      the cluster enforces; unused objects belong to no policy (shown under all policies only). Every
      count, summary and ACE saving of a one-policy view is that policy's own. The attack surface
      toolbar laid out as a form (label above field; the cluster filter hidden while a policy is chosen).

## Running work outside the plan

- [x] Temp ids are scoped per item inside a batch (`plan.item_ops`): every plan numbers its new objects from `new:1`, so 51 group compactions in one batch shared one object in the traffic proof (269 "changed" flows, approval blocked; found by the dry run, changeset 7).
- [x] Lab cleanup round 2 on the real FMC: changeset 3, 233 changes in 4 batches, all deployed.
- [x] Shadowed rules are never split / merged / tightened / renamed (found on the lab FMC).
- [x] Resumable rollback with an undo journal (found when the lab VPN dropped mid-batch).
- [x] Docker Hub 0.7.0 — unblocked by the 3.12.16 base image (no vendored packages needed).
