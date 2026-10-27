# Background jobs and their progress

Every background job is recorded in `job_runs` when it is queued and reports its progress while
it runs: pulls from the FMC, analysis, batch write + deploy, finishing a rollback, and the hourly
audit-chain check. (The 5-minute check for due scheduled pulls is not recorded; the pulls it
starts are, as requested by `system:scheduler`.)

| Job | Steps (share of 0–100 %) |
|---|---|
| Pull | objects per resource (2–30), devices and clusters (30–35), policies i/N with the rule count so far (35–85), interfaces and routes per cluster (85–93), live routing tables (93–99) |
| Analysis | objects, duplicates and groups (0–12), rules per policy (12–55), recommendations per policy (55–99) |
| Batch | writes i/N (2–60), verification (60–66), deployment — the FMC reports a state, not a percentage, so the bar advances with time and shows the state and seconds (66–98); on failure, rollback steps and redeploy |
| Finish rollback | undo steps i/N (2–60), deployment (60–98) |

* The worker writes through its own short transactions (the analysis itself is one long
  transaction), at most about once a second; progress never goes backwards.
* A job that ends without success records why (`auth_failed`, `unreachable`, …). A run still
  queued / running whose RQ job failed, stopped or vanished is marked failed (`worker_lost`)
  the next time anyone lists jobs; a run that never reached the queue, after 2 minutes
  (`not_queued`).
* `GET /api/jobs?state=active|finished|all&kind=&limit=` (policy:read; audit-chain runs only
  with audit:read).

UI: a jobs button in the top bar (spinner and count while something runs; a panel with progress
bars, steps and elapsed time); a notice when a job **you** started ends, with a link to its
result; *Monitor → Events & Logs → Jobs* for the history. The browser asks every 2 s while a job
is queued or running, every 15 s otherwise, every 30 s in a hidden tab — no manual refresh.
