# Security design and threat model

The system holds the full rulebase of every firewall and the credentials to change them.
It is treated as a **GOLD / crown-jewel asset**: whoever controls it controls the firewalls.
Baseline: OWASP ASVS / Top 10, CWE Top 25, deny-by-default in every layer.

## Threat model (summary)

| Asset | Threat | Controls |
|---|---|---|
| Write path to the FMC (phase 5) | Unauthorised or hasty change opens the firewall | Read-only by default; approver role required (admin ≠ approver); author ≠ approver; ticket id; batches capped by the per-cluster deploy limit in code; full audit |
| FMC API credentials | Theft from DB, backups, logs, memory | AES-256-GCM with context binding; master keyring only as a root-only Docker secret; never returned by the API; log masking; decrypted on demand into a buffer that is zeroised after use (Python cannot guarantee full memory scrubbing — documented limitation) |
| Session / UI | XSS, CSRF, session theft/fixation | Strict CSP (`script-src 'self'`, no inline), React escaping, `dangerouslySetInnerHTML` banned by lint, no web storage for security material (lint), `__Host-` HttpOnly Secure SameSite=Strict cookie, per-session CSRF token, session id rotation at login and password change, idle + absolute timeout |
| Local accounts | Brute force, credential stuffing | Argon2id, password policy, per-user and per-IP lockout, nginx rate limit, constant-work verification for unknown users, forced change of temporary passwords |
| Authorisation | Missing check on a new endpoint | Server-side RBAC dependency on every route; **route-guard test fails the build** if any route lacks a guard; denials are audited |
| Audit trail | Tampering / deletion | HMAC-SHA256 hash chain keyed from the master keyring; runtime DB role has no UPDATE/DELETE/TRUNCATE; trigger rejects changes from any role; hourly verification job publishes the head hash to the log stream (external anchor) |
| Database | SQL injection, privilege abuse | ORM / bound parameters only (ruff S608, review); separate owner (migrations) and runtime roles; runtime role has no DDL |
| Data from the FMC | Malicious/malformed config treated as instructions | Treated as untrusted data: strict pydantic validation with size limits; never executed or interpolated into queries/commands; response size cap |
| TLS to the FMC | MITM | Verification always on (CA + hostname, TLS ≥ 1.2); no setting or code path to disable it; tests prove wrong CA and wrong hostname are rejected |
| Background jobs | Code execution through the queue | JSON serializer only (no pickle); allow-list of job functions checked before forking; Redis password-protected on an internal network |
| Supply chain | Malicious/compromised dependency | Exact versions + hashes (`--require-hashes`), 14-day release age floor when locking, npm `ignore-scripts`, digest-pinned base images, offline builds from `vendor/`, pip-audit / npm audit / Trivy |
| Error handling | Information leakage | Fail-closed generic errors with request id; validation errors never echo input; no stack traces to clients; `hide_parameters` on SQL errors |

## Secrets

| Secret | Where | Used by |
|---|---|---|
| `db_admin_password` | `infra/secrets/` | postgres bootstrap only |
| `db_owner_password` | `infra/secrets/` | migrations |
| `db_app_password` | `infra/secrets/` | api, worker |
| `redis_password` | `infra/secrets/` | redis, api, worker, scheduler |
| `master_keyring` | `infra/secrets/` | api, worker (AES-GCM + audit HMAC) |

Created once by `scripts/init-secrets.*` (never overwritten, never printed). The directory
is `0700 root`; files are `0644` so the unprivileged container users can read their
per-file Docker secret mounts, while no other host user can traverse the directory.
`.env` holds no secrets. Pre-commit hook and `.gitignore` block secret files.

### Master key rotation (manual, supported from day one)

1. Generate a new 32-byte key: `head -c 32 /dev/urandom | base64`.
2. Edit `infra/secrets/master_keyring`: add `"k<date>": "<base64>"` under `keys` and set
   `"active"` to the new id. **Keep the old key** in `keys`.
3. `docker compose ... up -d api worker` (reload), then
   `docker compose ... exec api python -m app.cli rotate-secrets` — re-encrypts every
   stored credential with the active key (audited).
4. `docker compose ... exec api python -m app.cli verify-audit`.
5. Old keys must remain in the keyring while audit records signed with them must stay
   verifiable (the audit chain records the key id of every row).

## TLS material

* FMC trust store: `infra/trust/fmc-ca.pem` (internal CA of the FMC certificate).
* UI: `infra/certs/ui/ui.pem` + `ui.key` from the organisation's PKI; until then a
  self-signed default from `scripts/gen-certs --ui <host>`. Mounted per file.

## Security gates (scripts/ci.*, also the pre-push hook)

ruff (incl. bandit rules) · ruff format · mypy `--strict` · bandit · pytest (unit +
integration against real PostgreSQL/Redis/TLS mock, coverage ≥ 85 %) · eslint (typescript-eslint
strict-type-checked, security, no-unsanitized) with zero warnings · tsc strict · vitest ·
pip-audit + npm audit (online) or Trivy (offline). Any finding fails the gate.
