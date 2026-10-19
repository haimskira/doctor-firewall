#!/usr/bin/env bash
# Install / upgrade on the OFFLINE Linux production server. Run as root from the
# repository checkout (updated with `git pull` from the internal Git remote):
#
#   sudo scripts/install-offline.sh /path/to/doctor-firewall-bundle-<ver>-<sha>.tar
#
# Steps: verify checksums -> verify the bundle matches this checkout's commit ->
# docker load -> secrets/certs/trust checks -> migrations + start -> health.
# Nothing here touches the network.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BUNDLE="${1:-}"
[[ -f "$BUNDLE" ]] || die "usage: install-offline.sh <bundle.tar>"
[[ "$(id -u)" == "0" ]] || die "run as root (secrets and certificates must be root-owned)"
docker compose version >/dev/null 2>&1 \
    || die "the 'docker compose' plugin is missing (Ubuntu package: docker-compose-v2, installed offline)"

log "Verifying bundle checksum"
SIDE="$BUNDLE.sha256"
[[ -f "$SIDE" ]] || die "missing $SIDE next to the bundle"
(cd "$(dirname "$BUNDLE")" && sha256sum --quiet -c "$(basename "$SIDE")") || die "bundle checksum mismatch"
ok "bundle checksum OK"

WORK="$(mktemp -d /var/tmp/df-install.XXXXXX)"; trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xf "$BUNDLE"
DIR="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)"
(cd "$DIR" && sha256sum --quiet -c SHA256SUMS) || die "bundle content checksum mismatch"
ok "bundle contents verified"

read_manifest() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$DIR/manifest.json" "$1"; }
VERSION="$(read_manifest version)"
BUNDLE_SHA="$(read_manifest git_commit)"
HEAD_SHA="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
[[ "$BUNDLE_SHA" == "$HEAD_SHA" ]] \
    || die "bundle built from commit $BUNDLE_SHA but this checkout is $HEAD_SHA — git checkout $BUNDLE_SHA first"
ok "bundle $VERSION matches checkout $HEAD_SHA (Trivy DB: $(read_manifest trivy_db_downloaded_at))"

log "Loading images"
gunzip -c "$DIR/images.tar.gz" | docker load -q
log "Updating vendor/ (offline scanning)"
mkdir -p "$VENDOR"
rm -rf "$VENDOR/wheels" "$VENDOR/npm-cache" "$VENDOR/trivy-cache"
cp -r "$DIR/vendor/." "$VENDOR/"

log "Configuration"
if [[ ! -f "$INFRA/.env" ]]; then
    cp "$INFRA/.env.example" "$INFRA/.env"
    chmod 0600 "$INFRA/.env"
    ok "created infra/.env from the example — review it"
fi
sed -i "s/^DF_VERSION=.*/DF_VERSION=$VERSION/" "$INFRA/.env"
init_secret_dir "$INFRA/secrets"
CA_FILE="$(grep -E '^DF_FMC_CA_FILE=' "$INFRA/.env" | cut -d= -f2-)"
[[ -s "$INFRA/${CA_FILE#./}" ]] || die "FMC trust store ${CA_FILE} not found — see infra/trust/README.md"
TLS_DIR="$(grep -E '^DF_UI_TLS_DIR=' "$INFRA/.env" | cut -d= -f2-)"
[[ -s "$INFRA/${TLS_DIR#./}/ui.pem" && -s "$INFRA/${TLS_DIR#./}/ui.key" ]] \
    || die "UI certificate missing in ${TLS_DIR} — install the PKI cert or run: DF_VERSION=$VERSION scripts/gen-certs.sh --ui <hostname>"
chmod 0700 "$INFRA/secrets" "$INFRA/${TLS_DIR#./}"

log "Starting (migrations run first, automatically)"
docker compose --project-directory "$INFRA" -f "$INFRA/docker-compose.yml" --env-file "$INFRA/.env" up -d --wait
ok "Doctor Firewall $VERSION is running"
cat <<EOF

First installation only — create the first administrator (password prompt):
  docker compose --project-directory infra -f infra/docker-compose.yml exec api \\
      python -m app.cli create-user <name> --role admin
EOF
