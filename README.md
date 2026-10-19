# Doctor Firewall

Policy analysis and controlled enforcement for **Cisco Secure Firewall** (FMC 10.1 managing
~20 FTD HA clusters). It pulls each cluster's access-control policy, objects and network
configuration from the FMC **read-only**, analyses them against the firewall doctrine,
recommends clean-ups and SSL/IPS placement, and pushes changes **only** after explicit
approval, in batches that never exceed the deploy limit.

> **Status: phase 0 — secure foundation.** Authentication, RBAC, tamper-evident audit,
> encrypted credential storage, a verified-TLS FMC client (connection test), the FMC 10.1
> mock, the offline build/CI/bundle pipeline and the UI shell (Hebrew/English) are done.
> Data collection (phase 1) is next. See [docs/architecture.md](docs/architecture.md#roadmap).

The system is designed for an **air-gapped production network**: nothing at runtime talks to
anything except the FMC, and production installs from an offline bundle without internet.

---

## Repository layout

```
backend/     FastAPI API, RQ workers, CLI, Alembic migrations, tests (unit + integration)
frontend/    React + TypeScript (strict) UI, i18n he/en (RTL default), vitest
fmc-mock/    FMC 10.1 REST emulator for development/tests (never shipped)
infra/       Dockerfiles, docker-compose (prod / dev / CI), nginx, postgres init, redis
scripts/     Helper scripts: every *.sh has a matching *.ps1 for Windows PowerShell
docs/        Architecture, security & threat model, offline operations, decision log
vendor/      (git-ignored) wheels, npm cache, Trivy DB — produced by scripts/vendor
dist/        (git-ignored) offline bundles — produced by scripts/make-bundle
```

---

## Development — Windows (Docker Desktop + PowerShell)

Prerequisites: Docker Desktop (WSL2 backend, **≥ 6 GB memory** assigned to Docker),
Git for Windows (its `bash.exe` runs the shared scripts behind the `.ps1` entry points),
Python 3.12 (only for `scripts/lock-deps`).

```powershell
git clone https://github.com/haimskira/doctor-firewall.git
cd doctor-firewall
.\scripts\install-hooks.ps1      # pre-commit guard + pre-push CI gate
.\scripts\vendor.ps1             # ONLY step that uses the internet: wheels, npm cache, Trivy DB, base images
.\scripts\dev-up.ps1             # builds offline from vendor/, generates dev certs + secrets, starts everything
.\scripts\smoke-test.ps1         # end-to-end check over verified HTTPS (creates a throw-away admin)
```

Then create your own administrator (you will be asked for a password and must change it
at first login):

```powershell
docker compose --project-directory infra -f infra/docker-compose.yml -f infra/docker-compose.dev.yml `
    exec api python -m app.cli create-user admin --role admin
```

Open **https://localhost:8443**. To avoid browser warnings, import `infra/certs/dev-ca.pem`
as a trusted root (dev only). In *FMC connection*, the mock is host `fmc-mock`, port `443`,
user `api_user`, password in `infra/secrets/fmc_mock_password`.

| Task | Command |
|---|---|
| Full CI gate (lint, mypy/tsc strict, bandit, tests, SCA) | `.\scripts\ci.ps1` |
| Same, SCA from the offline Trivy DB | `.\scripts\ci.ps1 --offline` |
| Stop the dev stack | `.\scripts\dev-up.ps1 --down` |
| Re-lock dependencies after editing `*.in` / `package.json` | `.\scripts\lock-deps.ps1` then `.\scripts\vendor.ps1` |

Line endings are handled by `.gitattributes` (LF everywhere, CRLF for `*.ps1`), so scripts
and container files work on both platforms.

## Development — Linux

Same flow with the `.sh` scripts: `scripts/install-hooks.sh`, `scripts/vendor.sh`,
`scripts/dev-up.sh`, `scripts/smoke-test.sh`, `scripts/ci.sh`.

---

## Production — offline Linux server

The server has **no internet**. It receives code and compose files through `git pull` from
the internal Git remote, and the **offline bundle** (images + vendored deps + Trivy DB,
~2–3 GB) separately on approved media / `scp`. Bundles are never committed to Git.

Server prerequisites (installed offline by the platform team): Docker Engine and the
`docker compose` plugin (Ubuntu package `docker-compose-v2`), Python 3 (for the installer's
manifest check), x86-64.

**On the development machine** (commit first; the bundle records the exact commit):

```bash
scripts/make-bundle.sh 0.1.0     # runs the CI gate, builds, scans images offline, writes dist/*.tar + .sha256
```

**On the server** (as root, in the repository checkout):

```bash
git pull                                   # from the internal remote
git checkout <commit printed by make-bundle>
cp /path/to/fmc-ca.pem infra/trust/fmc-ca.pem          # CA that signs the FMC certificate
# UI certificate from the org PKI -> infra/certs/ui/ui.pem + ui.key
sudo scripts/install-offline.sh /path/to/doctor-firewall-bundle-0.1.0-<sha>.tar
# No PKI certificate yet? The installer stops after loading the images; then create a
# self-signed default and re-run the installer:
#   sudo DF_VERSION=0.1.0 scripts/gen-certs.sh --ui fw-doctor.corp.local
docker compose --project-directory infra -f infra/docker-compose.yml exec api \
    python -m app.cli create-user <name> --role admin
```

`install-offline.sh` verifies the bundle checksums, refuses a bundle built from a different
commit, loads the images, creates secrets if missing (never overwrites), checks the trust
store and UI certificate, runs migrations and starts the stack. Upgrades use the same command
with a newer bundle. Details, key rotation and patching: [docs/operations-offline.md](docs/operations-offline.md).

---

## Security in one paragraph

Read-only towards the FMC by default; every future write requires an approver, a ticket,
and a batch within the deploy limit. Server-side RBAC on every endpoint (enforced by a test
that fails the build if a route is unguarded). Sessions in HttpOnly/Secure/SameSite=Strict
`__Host-` cookies with CSRF tokens; Argon2id passwords; lockout. FMC credentials encrypted
with AES-256-GCM under a master keyring (Docker secret) with rotation. Append-only,
HMAC-chained audit log protected at the database level. Full TLS verification to the FMC —
there is no code path that disables it. Strict CSP, no inline scripts, no CDN. All
dependencies hash-pinned and vendored. See [docs/security.md](docs/security.md).
