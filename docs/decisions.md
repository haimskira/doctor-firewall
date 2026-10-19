# Decision log

Short records of choices that deviate from, or refine, the specification and the agreed
decisions. Newest first.

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
