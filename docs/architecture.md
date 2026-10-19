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
| `postgres` | `postgres:16` (digest-pinned) | system of record (JSONB + recursive CTEs for the object graph) |
| `redis` | `redis:7.4` (digest-pinned) | password-protected, admin commands disabled |
| `fmc-mock` | dev/CI only | FMC 10.1 emulator over TLS |

All containers run as non-root, `read_only` root FS, `cap_drop: ALL`, `no-new-privileges`
(postgres keeps the minimal capabilities its entrypoint needs).

## Backend layout (`backend/app`)

| Package | Responsibility |
|---|---|
| `core/` | settings (secrets from files), crypto keyring/AES-GCM, JSON logging with masking, error handling, ASGI security middleware, thread-safe singletons |
| `auth/` | Argon2id passwords, provider abstraction (`local` now; TACACS+/LDAP in phase 6 — roles stay local), Redis sessions, login throttle, RBAC + CSRF dependencies |
| `audit/` | HMAC hash-chained, append-only audit log |
| `fmc/` | FMC REST client (token lifecycle, verified TLS, response validation); version adapters arrive in phase 1 |
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
| Paging `offset/limit` (max 1000), `expanded=true`, hit counts | phase 1 |
| Limits: 300 GET/min/IP, 10 connections/IP, 1 write at a time, 2 MB payload | mock enforces all; client token bucket + Redis write lock in phase 1 / 5 |
| Writes: GET → merge → PUT with version; dependency ordering; bulk ≤ 1000 rules | phase 5 |
| Deploy as async job, poll `jobhistories` until DEPLOYED, rollback requests, ticket ids | phase 5 |

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Secure foundation: auth, RBAC, audit, secrets, FMC client core + connection test, mock, offline build/CI/bundle, UI shell (he/en) | **done** |
| 1 | Collection & mapping (MVP): version adapter 10.1, paged/checkpointed pull of policies, rules (order + category), objects, groups, zones, routes, hit counts; snapshots; object graph; faithful rulebase view; where-used / membership; basic duplicates | next |
| 2 | Analysis & score: ACE expansion, shadowing, dead rules/objects, asset table + bootstrap, explained rule score | |
| 3 | Recommendations: split/merge groups & rules, tightening, role naming, naming convention + renames, preview & deploy cost | |
| 4 | Connectivity map: three views, filtering, risk colouring, before/after | |
| 5 | Controlled enforcement: changesets, batching under the per-cluster deploy limit, approval, deploy, verification, rollback | |
| 6 | SSL/IPS recommendations; TACACS+ (ISE) and LDAP providers | |
