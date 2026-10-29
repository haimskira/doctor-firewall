#!/usr/bin/env bash
# Install / upgrade on the Linux production server from a registry (Docker Hub).
# Run as root from the repository checkout (compose files and scripts come from Git):
#
#   sudo DF_IMAGE_REPO=haim1418/doctor-firewall scripts/install-online.sh <x.y.z>
#
# Steps: pull the images -> verify they were built from this checkout's commit ->
# secrets/certs/trust checks -> migrations + start -> health.
# The air-gapped alternative is scripts/install-offline.sh with a bundle.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)?$ ]] \
    || die "usage: DF_IMAGE_REPO=<user>/<repo> install-online.sh <x.y.z>"
REPO="${DF_IMAGE_REPO:-}"
valid_image_repo "$REPO" || die "set DF_IMAGE_REPO (the repository the images were published to)"
[[ "$(id -u)" == "0" ]] || die "run as root (secrets and certificates must be root-owned)"
docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing (Ubuntu: docker-compose-v2)"

log "Pulling $REPO:*-$VERSION"
for component in "${RUNTIME_COMPONENTS[@]}"; do
    image="$(registry_image "$REPO" "$component" "$VERSION")"
    docker pull -q "$image" >/dev/null || die "cannot pull $image"
done
HEAD_SHA="$(git -C "$ROOT_HOST" rev-parse --short=12 HEAD)"
IMAGE_SHA="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$(registry_image "$REPO" api "$VERSION")")"
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
for component in "${RUNTIME_COMPONENTS[@]}"; do
    set_env "DF_IMAGE_${component^^}" "$(registry_image "$REPO" "$component" "$VERSION")"
done
init_secret_dir "$INFRA/secrets"
CA_FILE="$(grep -E '^DF_FMC_CA_FILE=' "$INFRA/.env" | cut -d= -f2-)"
[[ -s "$INFRA/${CA_FILE#./}" ]] || die "FMC trust store ${CA_FILE} not found — see infra/trust/README.md"
TLS_DIR="$(grep -E '^DF_UI_TLS_DIR=' "$INFRA/.env" | cut -d= -f2-)"
[[ -s "$INFRA/${TLS_DIR#./}/ui.pem" && -s "$INFRA/${TLS_DIR#./}/ui.key" ]] \
    || die "UI certificate missing in ${TLS_DIR} — install the PKI cert or run: DF_IMAGE_API=$(registry_image "$REPO" api "$VERSION") scripts/gen-certs.sh --ui <hostname>"
chmod 0700 "$INFRA/secrets" "$INFRA/${TLS_DIR#./}"

log "Starting (migrations run first, automatically)"
COMPOSE=(docker compose --project-directory "$INFRA" -f "$INFRA/docker-compose.yml" --env-file "$INFRA/.env")
# Site-local override (not in Git), e.g. extra_hosts for an FMC name DNS does not resolve.
[[ -f "$INFRA/docker-compose.local.yml" ]] && COMPOSE+=(-f "$INFRA/docker-compose.local.yml")
"${COMPOSE[@]}" up -d --wait
ok "Doctor Firewall $VERSION is running"
cat <<EOF

First installation only — create the first administrator (password prompt):
  docker compose --project-directory infra -f infra/docker-compose.yml exec api \\
      python -m app.cli create-user <name> --role admin
EOF
