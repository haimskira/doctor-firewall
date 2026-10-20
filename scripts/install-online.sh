#!/usr/bin/env bash
# Install / upgrade on the Linux production server from a registry (Docker Hub).
# Run as root from the repository checkout (compose files and scripts come from Git):
#
#   sudo DF_IMAGE_PREFIX=myuser/doctor-firewall- scripts/install-online.sh <x.y.z>
#
# Steps: pull the images -> verify they were built from this checkout's commit ->
# secrets/certs/trust checks -> migrations + start -> health.
# The air-gapped alternative is scripts/install-offline.sh with a bundle.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)?$ ]] \
    || die "usage: DF_IMAGE_PREFIX=<user>/doctor-firewall- install-online.sh <x.y.z>"
PREFIX="${DF_IMAGE_PREFIX:-}"
valid_image_prefix "$PREFIX" || die "set DF_IMAGE_PREFIX (the same prefix the images were published with)"
[[ "$(id -u)" == "0" ]] || die "run as root (secrets and certificates must be root-owned)"
docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing (Ubuntu: docker-compose-v2)"

log "Pulling ${PREFIX}*:$VERSION"
for component in "${RUNTIME_COMPONENTS[@]}"; do
    docker pull -q "${PREFIX}${component}:$VERSION" >/dev/null || die "cannot pull ${PREFIX}${component}:$VERSION"
done
HEAD_SHA="$(git -C "$ROOT_HOST" rev-parse --short=12 HEAD)"
IMAGE_SHA="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${PREFIX}api:$VERSION")"
[[ "$IMAGE_SHA" == "$HEAD_SHA" ]] \
    || die "images were built from commit $IMAGE_SHA but this checkout is $HEAD_SHA — git checkout $IMAGE_SHA first"
ok "images $VERSION match checkout $HEAD_SHA"

log "Configuration"
if [[ ! -f "$INFRA/.env" ]]; then
    cp "$INFRA/.env.example" "$INFRA/.env"
    chmod 0600 "$INFRA/.env"
    ok "created infra/.env from the example — review it"
fi
set_env() {
    if grep -qE "^$1=" "$INFRA/.env"; then
        sed -i "s#^$1=.*#$1=$2#" "$INFRA/.env"
    else
        printf '%s=%s\n' "$1" "$2" >> "$INFRA/.env"
    fi
}
set_env DF_VERSION "$VERSION"
set_env DF_IMAGE_PREFIX "$PREFIX"
init_secret_dir "$INFRA/secrets"
CA_FILE="$(grep -E '^DF_FMC_CA_FILE=' "$INFRA/.env" | cut -d= -f2-)"
[[ -s "$INFRA/${CA_FILE#./}" ]] || die "FMC trust store ${CA_FILE} not found — see infra/trust/README.md"
TLS_DIR="$(grep -E '^DF_UI_TLS_DIR=' "$INFRA/.env" | cut -d= -f2-)"
[[ -s "$INFRA/${TLS_DIR#./}/ui.pem" && -s "$INFRA/${TLS_DIR#./}/ui.key" ]] \
    || die "UI certificate missing in ${TLS_DIR} — install the PKI cert or run: DF_VERSION=$VERSION DF_IMAGE_PREFIX=$PREFIX scripts/gen-certs.sh --ui <hostname>"
chmod 0700 "$INFRA/secrets" "$INFRA/${TLS_DIR#./}"

log "Starting (migrations run first, automatically)"
docker compose --project-directory "$INFRA" -f "$INFRA/docker-compose.yml" --env-file "$INFRA/.env" up -d --wait
ok "Doctor Firewall $VERSION is running"
cat <<EOF

First installation only — create the first administrator (password prompt):
  docker compose --project-directory infra -f infra/docker-compose.yml exec api \\
      python -m app.cli create-user <name> --role admin
EOF
