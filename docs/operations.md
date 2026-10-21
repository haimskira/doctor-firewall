# Operations — deploy through Docker Hub

Development happens on Windows (Docker Desktop). Production is a Linux server (Ubuntu 24.04,
Docker 29 + compose plugin) **with internet access**: it pulls the images from a registry
(Docker Hub) and the compose files / scripts from Git. The air-gapped path with an offline
bundle still exists — see [operations-offline.md](operations-offline.md).

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

## 2. Install / upgrade (production server, root)

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

## Runtime network

Internet access on the server is used to pull images and code. The running application still
talks **only to the FMC** (and its own containers); no telemetry, update checks or CDNs —
fonts and icons are bundled into the web image.

## Day-2

Upgrade = publish a new version, then on the server `git checkout <commit>` and
`install-online.sh <new version>` (migrations run automatically). Rollback = the same with the
previous version and commit (migrations are forward-compatible within a minor version; take a
backup before upgrades — see [operations-offline.md](operations-offline.md#backups)).
