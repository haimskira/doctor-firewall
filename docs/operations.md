# Operations — Docker Hub to an offline server

Three machines, in this order:

| Machine | Network | Role |
|---|---|---|
| Development (Windows, Docker Desktop) | internet | CI gate, build, scan, **publish** to Docker Hub |
| Staging Linux (Ubuntu 24.04, Docker 29) | internet | **pull** the published images and **export** a transfer bundle |
| Production server (Ubuntu 24.04, Docker 29) | **no internet**, reaches only the FMC | **install** from the bundle and run |

The production server never needs the internet — not to install, start, restart, upgrade or scan:
every image is loaded from the bundle, compose is set to `pull_policy: never` for every service
(a missing image fails loudly instead of trying a registry), fonts and icons are inside the web
image, and the vulnerability DB for offline scans travels with the bundle.

## 1. Publish (development machine)

```bash
docker login                                  # your Docker Hub account; nothing is stored in the repo
git status                                    # clean tree, the commit you want to ship
DF_IMAGE_REPO=haim1418/doctor-firewall scripts/publish-images.sh 0.5.0
```

PowerShell: `$env:DF_IMAGE_REPO='haim1418/doctor-firewall'; scripts\publish-images.ps1 0.5.0`.

The script runs the full CI gate, builds the runtime images labelled with the version and the Git
commit, scans them with Trivy (fixable HIGH / CRITICAL block the push) and pushes:

Repository: one Docker Hub repository, one tag per component (`haim1418/doctor-firewall`).

| Tag | Content |
|---|---|
| `api-<ver>` | FastAPI API, RQ workers, scheduler, CLI, migrations |
| `web-<ver>` | nginx with the built UI (no Node at runtime) |
| `postgres-<ver>` | PostgreSQL 16 without gosu, runs as `postgres` |
| `redis-<ver>` | the pinned Redis image, re-tagged |

The images contain the application code (public in this repository anyway) and **no secrets**:
passwords, the master keyring, TLS keys and the FMC trust store are files mounted at runtime from
`infra/secrets`, `infra/certs` and `infra/trust` on the server. Repositories may stay public or
be made private on Docker Hub (then `docker login` on the server too).

## 2. Export a bundle (staging Linux with internet)

```bash
git clone https://github.com/haimskira/doctor-firewall.git && cd doctor-firewall   # first time
git fetch && git checkout <commit printed by publish>
DF_IMAGE_REPO=haim1418/doctor-firewall scripts/export-images.sh 0.5.0
```

`export-images.sh` pulls the four images, refuses to continue if they were built from a different
commit than the checkout, re-tags them to local names (`doctor-firewall/<component>:<ver>`),
downloads the Trivy scanner and its vulnerability DB, scans the images offline (fixable HIGH /
CRITICAL fail) and writes `dist/doctor-firewall-bundle-<ver>-<sha>.tar` + `.sha256` with:

| File | Content |
|---|---|
| `images.tar.gz` | api, web, postgres, redis, trivy |
| `source.tar.gz` | the code at that commit (compose files, scripts, docs) + `.df-commit` |
| `vendor/trivy-cache` | vulnerability DB (date recorded in the manifest) |
| `manifest.json`, `SHA256SUMS` | version, commit, image ids; checksums of everything |

Carry both files (`.tar` and `.tar.sha256`) to the production server on approved media.

## 3. Install / upgrade (offline production server, root)

```bash
mkdir -p /opt/doctor-firewall && cd /opt/doctor-firewall
B=/media/doctor-firewall-bundle-0.5.0-<sha>.tar
(cd "$(dirname "$B")" && sha256sum -c "$(basename "$B").sha256")
tar -xOf "$B" --wildcards '*/source.tar.gz' | tar -xz        # the code of that commit
# first time: FMC CA -> infra/trust/fmc-ca.pem ; UI cert -> infra/certs/ui/ui.pem + ui.key
sudo scripts/install-offline.sh "$B"
```

`install-offline.sh` verifies both checksum layers, refuses a bundle whose commit differs from
the extracted code (`.df-commit`), loads the images, refreshes `vendor/trivy-cache`, writes
`DF_VERSION` and clears any registry image names in `infra/.env`, creates missing secrets (never
overwrites), checks the trust store and UI certificate, runs the migrations and starts the stack.
Upgrades: the same commands with the new bundle — `infra/.env`, `infra/secrets`, `infra/certs`,
`infra/trust` and the data volumes are not in the source archive and are kept.
Day-2 commands and backups: [operations-offline.md](operations-offline.md).

## Alternative: production server with internet

```bash
git clone https://github.com/haimskira/doctor-firewall.git /opt/doctor-firewall   # first time
cd /opt/doctor-firewall && git fetch && git checkout <commit printed by publish>
# first time: FMC CA -> infra/trust/fmc-ca.pem ; UI cert -> infra/certs/ui/ui.pem + ui.key
sudo DF_IMAGE_REPO=haim1418/doctor-firewall scripts/install-online.sh 0.5.0
```

`install-online.sh` pulls the four images, refuses to continue if they were built from a different
commit than the checkout, writes `DF_VERSION` and `DF_IMAGE_API` / `_WEB` / `_POSTGRES` / `_REDIS` into `infra/.env`, creates any
missing secrets (never overwrites), checks the FMC trust store and the UI certificate, runs the
migrations and starts the stack (`up --wait`). First installation: create the first administrator
with the command it prints.

Building on the server instead of pulling is also possible (`git pull`, then
`scripts/vendor.sh` and `scripts/make-bundle.sh`), but publishing from the development machine
keeps the CI gate and the scan in one place.

Both install scripts also apply `infra/docker-compose.local.yml` when it exists (site-local, not in
Git — e.g. `extra_hosts` mapping the FMC's certificate name to its address). Any manual
`docker compose ... up` must pass it too, or the containers lose that mapping.

## Runtime network

The running application talks **only to the FMC** (and its own containers); no telemetry, update
checks or CDNs. This holds in both installation modes.

## Day-2

Upgrade = publish a new version, export a new bundle and install it (or `install-online.sh` on an
internet-connected server); migrations run automatically. Rollback = install the previous bundle
(migrations are forward-compatible within a minor version; take a backup before upgrades — see
[operations-offline.md](operations-offline.md#backups)).
