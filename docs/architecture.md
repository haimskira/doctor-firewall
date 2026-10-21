# Architecture

Source of truth for requirements: the system specification and the firewall doctrine
(kept outside the public repository). This document describes how the code realises them.

## Runtime topology (single host, docker compose)

```
              browser (HTTPS, verified)
                     │
             ┌───────▼────────┐   edge network (published port)
             │ web (nginx)    │   static UI + /api reverse proxy, CSP & security headers
             └───────┬────────┘
     backend network │ (internal: no route off the host)
   ┌─────────────────┼───────────────────────────────┐
   │        ┌────────▼───────┐      ┌──────────────┐ │
   │        │ api (FastAPI)  │◄────►│ redis        │ │ sessions, RQ queues, locks,
   │        └───┬────────┬───┘      └──────▲───────┘ │ rate-limit buckets
   │            │        │                 │         │
   │   ┌────────▼──┐  ┌──▼────────┐  ┌─────┴──────┐  │
   │   │ postgres  │  │ worker(s) │  │ scheduler  │  │
   │   └───────────┘  └──┬────────┘  └────────────┘  │
   └─────────────┬───────┼──────────────────────────┘
        fmc net  │       │  (egress only to the FMC VIP; restrict on the host firewall)
              ┌──▼───────▼──┐
              │ FMC (HA VIP)│  REST API, read-only by default
              └─────────────┘
```

| Service | Image | Role |
|---|---|---|
| `web` | `doctor-firewall/web` (nginx-unprivileged) | TLS termination, static UI, `/api` proxy, login rate limit |
| `api` | `doctor-firewall/api` | REST API, RBAC, sessions, audit, FMC connection test |
| `worker` | same image, `python -m app.workers.worker` | RQ jobs (JSON serializer, allow-listed functions) |
| `scheduler` | same image, `python -m app.workers.scheduler` | periodic jobs (interval slots claimed in Redis) |
| `migrate` | same image, `alembic upgrade head` | one-shot, runs as schema owner before api/worker start |
| `postgres` | `doctor-firewall/postgres` (from digest-pinned `postgres:16.15`) | system of record (JSONB + recursive CTEs for the object graph); starts as `postgres`, gosu removed |
| `redis` | `redis:7.4` (digest-pinned) | password-protected, admin commands disabled |
| `fmc-mock` | dev/CI only | FMC 10.1 emulator over TLS |

All containers run as non-root from the first process, `read_only` root FS,
`cap_drop: ALL` (nothing added back), `no-new-privileges`.

## Backend layout (`backend/app`)

| Package | Responsibility |
|---|---|
| `core/` | settings (secrets from files), crypto keyring/AES-GCM, JSON logging with masking, error handling, ASGI security middleware, thread-safe singletons |
| `auth/` | Argon2id passwords, provider abstraction (`local` now; TACACS+/LDAP in phase 6 — roles stay local), Redis sessions, login throttle, RBAC + CSRF dependencies |
| `audit/` | HMAC hash-chained, append-only audit log |
| `fmc/` | FMC REST client (token lifecycle, verified TLS, token-bucket throttle, 429 backoff, paging), `normalize` (canonical values), `records` (version-neutral records), `adapters/` (FMC 10.1) |
| `collector/` | snapshot lifecycle (`runner`), staged checkpointed collection (`service`), bulk storage (`store`), rule match signature |
| `analysis/` | graph algorithms (cycles, depth, duplicate paths), match spaces (`space`), group expansion (`expand`), shadowing (`shadow`), scoring (`score`), asset bootstrap, phase-1/2 findings |
| `api/` | routers; every route declares a guard (enforced by test) |
| `models/` + `alembic/` | ORM models, migrations (run as owner role) |
| `workers/` | queues, jobs, allow-list worker, scheduler |
| `tools/` | certificate generation |
| `cli.py` | create-user, rotate-secrets, verify-audit |

## FMC 10.1 API procedures (implemented / planned)

| Procedure | Status |
|---|---|
| Token: `generatetoken` (Basic, empty body) → `X-auth-access-token`, refresh token, `DOMAIN_UUID` | done |
| Reuse one token; refresh ≤ 3 times then regenerate; revoke at end | done (per session); shared cross-worker token manager in phase 1 |
| `Domain_UUID` kept as a parameter (single Global domain today) | done (stored per connection) |
| Verified TLS against internal trust store, hostname checked | done |
| Paging `offset/limit` (max 1000), `expanded=true`, hit counts per device | done |
| Limits: 300 GET/min/IP, 10 connections/IP | done: token bucket (default 240/min) + concurrency cap (4) + 429 backoff with `Retry-After` |
| 1 write at a time, 2 MB payload | Redis write lock per FMC + sequential writes (phase 5); mock enforces |
| Writes: GET → merge → PUT; dependency ordering | done: GET + `expect` drift check → full PUT; ordered plans (bulk insert not used: one rule per POST keeps undo exact) |
| Deploy as async job, poll until DEPLOYED, rollback, ticket ids | done: `deploymentrequests` + `job/taskstatuses` polling; rollback by recorded undo + redeploy; ticket id in the audit trail (FMC change-management tickets: to verify) |

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Secure foundation: auth, RBAC, audit, secrets, FMC client core + connection test, mock, offline build/CI/bundle, UI shell (he/en) | **done** |
| 1 | Collection & mapping (MVP): version adapter 10.1, paged/checkpointed pull of policies, rules (order + category), objects, groups, zones, interfaces, static routes, BGP, hit counts; snapshots with retention and auto-sync; object graph; faithful rulebase view; where-used / membership; basic duplicates, nesting, cycles, literals, unused | **done** |
| 2 | Analysis & score: ACE expansion, shadowing / overlaps, dead rules, asset table (manual, CSV, bootstrap + confirm), per-cluster limits, explained rule score — see [scoring.md](scoring.md) | **done** |
| 3 | Recommendations: split/merge groups & rules, tightening, role naming, naming convention + renames, preview (inline / split) & deploy cost, local accept / dismiss — see [recommendations.md](recommendations.md); UI in the current FMC look ([ui-design.md](ui-design.md)) | **done** |
| 4 | Connectivity map: three views, filtering, risk colouring, before/after — see [connectivity.md](connectivity.md) | **done** |
| 5 | Controlled enforcement: executable plans, changesets, batching under the per-cluster deploy limit, four-eyes approval, drift-checked writes, verification, deploy, rollback — see [enforcement.md](enforcement.md) | **done** |
| 6 | SSL/IPS recommendations; TACACS+ (ISE) and LDAP providers | next |

## Collection (phase 1)

```
POST /api/fmc/connections/{id}/collect      (collect:run)   -> snapshot "pending" -> RQ "collect"
worker: run_collection
  token -> serverversion -> select_adapter("10.1") (unknown versions are refused)
  objects (15 resource types, paged, checkpointed per page)
  devices + HA pairs + policy assignments -> clusters
  policies of every kind (inventory): access, prefilter, decryption, identity, NAT,
    intrusion, file, DNS — and which clusters each one governs
  rules (paged; count verified per sub-resource): assigned access policies (+ categories,
    hit counts per unit), prefilter, decryption, identity, NAT (manual + auto)
  per cluster (primary unit): interfaces (4 kinds), IPv4 static routes, BGP
  stub objects for referenced-only ids (applications, …); connected routes from interfaces
  -> "complete" -> RQ "analysis" -> findings -> analyzed_at
```

* **Read-only**: GET only (plus the token lifecycle).
* **Resume**: `POST /api/snapshots/{id}/resume` continues a failed run from the last committed page.
* **Consistency**: if a policy's collected rule count differs from the FMC's total (config changed
  mid-pull), that policy is discarded and the run fails with `config_changed`; resume re-reads it.
* **Auto-sync**: per connection `sync_interval_minutes` (15–10080); the scheduler checks every 5 min.
* **Retention**: newest `DF_SNAPSHOT_RETENTION` (default 10) finished snapshots per connection.
* **Runtime routing table**: the config API provides interfaces, static routes and BGP neighbours;
  BGP-learned routes (the device's live routing table) are not part of the configuration API and
  are not collected yet — see the open question in the phase-1 report.

### Payload validation before production

The 10.1 adapter's schemas follow the documented API and the FMC mock. Before the first pull from
the production FMC, run a collection against it in a test window and review any `unexpected_response`
failure: the error names the resource, the item id and the offending fields (never values). Real,
sanitised payloads (accessrules `expanded=true`, networkgroups, hitcounts, ipv4staticroutes) can be
added as adapter test fixtures to lock the behaviour in.

## Policy dependencies

| Kind | FMC resource | Rules | How it is tied to a cluster |
|---|---|---|---|
| Access control | `policy/accesspolicies` | `accessrules` (+ categories, hit counts) | policy assignment |
| Prefilter | `policy/prefilterpolicies` | `prefilterrules` (PREFILTER / TUNNEL; ANALYZE / BLOCK / FASTPATH) | `prefilterPolicySetting` on the access policy |
| Decryption (SSL) | `policy/decryptionpolicies` | `decryptionpolicyrules` | any `*PolicySetting` the FMC returns on the access policy (see below) |
| Identity | `policy/identitypolicies` | `identityrules` | as above |
| NAT | `policy/ftdnatpolicies` | `manualnatrules`, `autonatrules` | policy assignment |
| Intrusion | `policy/intrusionpolicies` | inventory only (referenced by access rules) | via access rules |
| File / malware | `policy/filepolicies` | inventory only (referenced by access rules) | via access rules |
| DNS | `policy/dnspolicies` | inventory only | — |

All rule-bearing policies share one rules / references model, so the object explorer's
where-used and the unused-object finding account for every policy type (an object used only
by NAT is "used").

**Linkage discovery.** Cisco documents `prefilterPolicySetting` on the access policy but not how
the access policy references its decryption or identity policy in the 10.1 REST payload. The
adapter therefore records *every* `*PolicySetting` reference present on an access policy rather
than hard-coding a guessed field name, and all decryption / identity policies are collected even
when no link is found (they are shown as "not linked to a cluster"). Validate on the production
FMC (API Explorer or the first pull) and pin the field name once confirmed.
