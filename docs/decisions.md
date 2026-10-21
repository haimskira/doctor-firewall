# Decision log

Short records of choices that deviate from, or refine, the specification and the agreed
decisions. Newest first.

### D-028 — Directory sign-in: own TACACS+ client, ldap3 for LDAP
TACACS+ (RFC 8907, PAP + authorization) is a small, well-specified protocol and the only
Python client is unmaintained since 2019, so the client is implemented here (~200 lines,
tested against a fake server). LDAP uses `ldap3` (pure Python, mature). Local accounts never
consult a directory (break-glass); directory accounts have no local password. When the
directory manages roles they are replaced at every sign-in and an account without a mapped
role is refused; otherwise roles stay local and an administrator pre-creates the account.

### D-027 — Inspection: IPS / file executable, decryption advisory
Attaching an intrusion / file policy to an access rule is a normal executable plan
(`set_inspection`, drift-checked on action and policy ids). Decryption rules are proposals only:
known-key decryption needs server certificates and keys the system does not hold, and the
decryption-rule API differs from access rules. Tier -> policy mapping is configurable
(*Inspection profiles*), defaulting to Cisco's built-in intrusion policies; strength is judged
by name or base policy, and unknown custom policies are not second-guessed. A rule given an
intrusion policy without a variable set gets the FMC's built-in `Default-Set`.

### D-026 — Assets with components
The asset table was flat (one row per network). Assets are now first-class: an asset is a whole
system, a single server, a single user or a user segment, carries the doctrine classification
(tier, user type, owner), and holds components — each with a name, address / subnet / range,
role, ports and notes. Components inherit the asset's classification; the analysis and the map
see one node per asset (`TIER|ASSET`). Migration 0008 groups existing confirmed entries by
(system, tier); stand-alone entries and unconfirmed suggestions keep working. The CSV format
gains two optional columns, `asset` and `asset_kind`.

### D-025 — Offline production fed from the registry
Production has no internet. A staging Linux with internet pulls the images published to Docker
Hub, verifies their commit label, re-tags them to local names and exports a bundle that also
carries the source at that commit and the Trivy DB. Compose uses `pull_policy: never` on every
service so nothing on the server can ever reach for a registry.

### D-024 — Rollback by recorded undo, not FMC rollback requests
Every write records the inverse operation (the full original object for a PUT, a DELETE for a
create, a re-create with mapped ids for a delete). On any failure the writer undoes in reverse
and redeploys. FMC `rollbackrequests` restores a whole previous deployment, which could also undo
changes made by others in the meantime; the recorded undo touches only what the batch changed.

### D-023 — Drift check instead of object versions
The FMC REST API (unlike FDM) does not expose a version for optimistic locking on every object.
Before each write the executor re-reads the object and compares the name and the identities of
exactly the fields / members it will change with the snapshot (`expect`). Any difference stops
the batch before that write.

### D-022 — Security exceptions to the 14-day release-age floor
Locks only accept releases older than 14 days (supply-chain protection). A fix for a known
vulnerability may be taken earlier, one package at a time, through
`scripts/lock-exceptions.txt` (package, cutoff, advisory, reason); the line is removed once the
release is older than 14 days. First use: certifi 2026.10.19 for GHSA-6q48-6c7w-9gw2 (the FMC
client verifies against the internal CA, not certifi's bundle, but the SCA gate stays strict).

### D-021 — FMC look with open assets only
The product owner wants the UI to look exactly like the current FMC. It is rebuilt with open
assets bundled into the web image: the Inter font (OFL-1.1), Phosphor icons (MIT) and our own
CSS reproducing the layout, spacing and colours (dark top bar, Monitor / Manage / Administration
sidebar with flyouts, summary dashboard with closable widgets and bar tables, policy editor).
Cisco's proprietary assets — logo, product name, stylesheets, fonts — are **not** copied: the
repository is public and the tool must not present itself as a Cisco product. The brand area shows
our own mark and name in the same position.

### D-020 — Production pulls images from Docker Hub (supersedes the air-gapped assumption)
Stated by the product owner on 2026-10-20: production is a Linux server with internet access in
another environment; images are published to Docker Hub and pulled there, code comes from Git.
`scripts/publish-images.*` (CI gate + Trivy scan + push) and `scripts/install-online.sh` (pull,
commit check, migrations, start) are the primary path; the offline bundle remains available.
The runtime still talks only to the FMC. Registry: one repository with a tag per component
(`haim1418/doctor-firewall:api-<ver>` ...); compose takes `DF_IMAGE_<COMPONENT>`, defaulting to
the local names.

### D-019 — Connectivity map from rules, not traffic
The spec's map shows source → destination with port, hits and rule score. Without flow data
(out of scope; the system talks only to the FMC) the map is built from the rules that can match:
nodes are asset-table systems, edges the permit rules between them, coloured by the doctrine
rules in [connectivity.md](connectivity.md). Hits are the rules' hit counts, not per-flow counts.

### D-018 — Cytoscape.js for graphs
The spec names Cytoscape.js or sigma.js. Cytoscape.js 3.34.3: MIT, no runtime dependencies, its
own TypeScript types, compound nodes for tier columns. Its one inline `<style>` is suppressed with
a placeholder element so the CSP stays `style-src 'self'`.

### D-017 — Naming convention: token semantics and a separate permission
The spec says the administrator defines the convention and the system derives names from the
asset table and the rule. The exact token set and its meaning are ours (see
[recommendations.md](recommendations.md#naming-convention)); unresolvable tokens produce no
proposal instead of a guess. Defining the convention is a new permission,
`conventions:manage`, held by `admin` only (admin still has no changeset or deploy rights).
Names longer than 64 characters are not proposed — the FMC limit per object type is *to verify*.

### D-016 — Decisions are kept per fingerprint, across snapshots
Recommendations are recomputed by every analysis. An operator's accept / dismiss is stored by a
fingerprint of the proposal (kind, targets, before / after content, without rule positions), so it
survives the next pull and lapses automatically when the rule, the object or the proposal changes.
Admin has no `changeset:write` and cannot decide (separation of duties).

### D-015 — Deploy cost = FMC write operations
The spec asks for the deploy cost of each recommendation without defining the unit. We count
FMC write operations (object / rule create, update or delete = 1 each); a rename is 1 because
references are by id. Phase 5 batches against the per-cluster deploy limit in the same unit —
*to verify* on the real FMC whether its change limit counts objects, rules or deploy items.

### D-014 — ACE count is an estimate (upper bound with Object Group Search)
Per rule, ACEs = product of the leaf counts of zones, networks and ports on both sides. This is
how the FMC flattens groups; with Object Group Search enabled on a device the real count is
lower. Platform limits are per cluster and default to an explicitly *unverified* value.

### D-013 — USERS classification in the asset table
The doctrine keeps user space outside the server tiers. Instead of forcing user networks into a
tier, the asset table has a `USERS` classification (with `user_type`: FIN / IT / General ...).
Tier-skip scoring applies only between server tiers.

### D-012 — Policy links discovered from `*PolicySetting`, not guessed
The access-policy field that references the decryption / identity policy is not documented for
the FMC 10.1 REST API. Instead of guessing a name, the adapter records every `*PolicySetting`
reference returned (documented: `prefilterPolicySetting`), and collects all decryption / identity
policies regardless. Confirm the field on the real FMC before relying on cluster linkage.

### D-011 — Dependency age floor for npm as well
New npm dependencies are pinned to the newest release at least 14 days old (same rule as the
Python lock's `--exclude-newer`), e.g. `@tanstack/react-virtual` 3.14.13.

### D-010 — Derived PostgreSQL image without gosu
The offline image gate found 25 fixable HIGH/CRITICAL issues in `gosu` (static Go binary,
old Go stdlib) in both the Debian and Alpine `postgres:16.15` images. We never need it:
`infra/docker/postgres.Dockerfile` removes it and starts as `postgres` directly, which also
lets the container run with `cap_drop: ALL` and a read-only root FS. The role bootstrap
script is baked into the image.

### D-009 — nginx 1.30.6 alpine-slim base
`nginx-unprivileged:1.28.2-alpine` had fixable HIGH/CRITICAL CVEs (nginx, pcre2, zlib,
libtiff). The current stable line on the `-slim` variant (no image-filter/njs modules) scans
clean.

### D-008 — PowerShell scripts delegate to the POSIX scripts
Every `scripts/*.ps1` runs the matching `*.sh` through Git for Windows' `bash.exe`. One
implementation means Windows and Linux execute identical logic and cannot drift; Git for
Windows is already required for development.

### D-007 — TypeScript 6.0 instead of 7.0
TypeScript 7 (native compiler) is not supported by `typescript-eslint` (peer range
`<6.1`), which provides the strict type-aware lint rules we gate on. Revisit when supported.

### D-006 — `eslint-plugin-react` dropped
It does not support ESLint 10. Its relevant security rule (`no-danger`) is replaced by a
`no-restricted-syntax` rule banning `dangerouslySetInnerHTML`; hooks rules come from
`eslint-plugin-react-hooks`.

### D-005 — `httpx2` as a test-only dependency
Starlette ≥ 1.x's `TestClient` uses `httpx2` (the httpx successor). It is only in
`requirements-dev.txt`; the runtime FMC client uses `httpx` with an explicit SSL context.

### D-004 — Own interval scheduler instead of `rq-scheduler` / `rq cron`
Agreed decision: RQ with periodic sync. `rq-scheduler` pulls an sdist-only dependency
(`crontab`, cannot be installed offline without a build toolchain) and `freezegun` at
runtime; RQ's built-in cron enqueues with the **pickle** serializer, which conflicts with
"no unsafe deserialization". `app/workers/scheduler.py` (~40 lines) claims each interval
slot with Redis `SET NX` and enqueues with RQ's JSON serializer. Workers execute only
allow-listed functions.

### D-003 — An `admin` role in addition to viewer / optimizer / approver
User, FMC-connection and settings management need an owner. `admin` deliberately does
**not** include changeset or deploy permissions: pushing to a firewall always requires the
explicit `approver` role. Users may hold several roles.

### D-002 — Server-side sessions instead of JWT
An opaque id in a `__Host-` HttpOnly cookie, state in Redis (stored under the id's hash),
CSRF token per session. Allows immediate revocation (logout, deactivation, password
change) and keeps tokens out of JavaScript.

### D-001 — Thread-safe singletons for engine / Redis / keyring
`functools.lru_cache` is not atomic; concurrent first calls created duplicate SQLAlchemy
engines whose connections leaked (found by the integration suite).
`app/core/singleton.py` initialises under a lock.
