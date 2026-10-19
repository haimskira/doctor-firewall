# Offline operations

## Delivery model

| What | How it reaches the server |
|---|---|
| Code, compose files, scripts, docs | `git pull` from the internal Git remote |
| Docker images, vendored wheels/npm cache, Trivy DB | offline bundle (`dist/*.tar` + `.sha256`) on approved media / `scp` — **never in Git** |
| Secrets | generated on the server (`init-secrets`), never transferred |
| FMC CA / UI certificate | provided by the PKI team, copied into `infra/trust/` and `infra/certs/ui/` |

A bundle records the commit it was built from; `install-offline.sh` refuses to install it
on a checkout at a different commit, so code and images can never drift apart.

## Build a bundle (development machine, internet allowed)

```bash
scripts/vendor.sh                 # refresh wheels, npm cache, Trivy DB, base images
git commit ... && git push        # bundle must be built from a committed tree
scripts/make-bundle.sh 0.2.0      # CI gate -> runtime images -> offline image scan -> dist/
```

Image scan policy: fixable HIGH/CRITICAL vulnerabilities fail the bundle. Lock files are
scanned for all severities by the CI gate.

## Install / upgrade (offline server, root)

```bash
git pull && git checkout <commit>
sudo scripts/install-offline.sh /media/doctor-firewall-bundle-0.2.0-<sha>.tar
```

Migrations run automatically (`migrate` service) before `api`/`worker` start. Data volumes
(`pgdata`, `redisdata`) are preserved across upgrades.

## Patching / vulnerability DB refresh

The Trivy DB ages from the moment it is downloaded; its date is printed by
`scripts/scan-offline.sh` and stored in every bundle manifest. Refresh cadence is part of
the patching procedure: rebuild a bundle (even with unchanged code) to ship a fresh DB and
patched base images, then run `scripts/scan-offline.sh` on the server.

## Day-2 commands (server)

```bash
C="docker compose --project-directory infra -f infra/docker-compose.yml"
$C ps                                             # status / health
$C logs -f api worker                             # JSON logs (secrets masked)
$C exec api python -m app.cli create-user <name> --role viewer --role optimizer
$C exec api python -m app.cli verify-audit        # exit 1 if the chain is broken
$C exec api python -m app.cli rotate-secrets      # after changing the active key
scripts/scan-offline.sh                           # offline vulnerability scan
```

Database access for inspection (psql / DBeaver) goes through the `postgres` container on
the internal network, e.g. `$C exec postgres psql -U postgres -d doctor_firewall`; do not
publish the database port.

## Backups

Back up the `pgdata` volume (or `pg_dump` via the container) **and** `infra/secrets/`
(separately, encrypted): stored FMC credentials and audit signatures cannot be verified or
decrypted without the master keyring.
