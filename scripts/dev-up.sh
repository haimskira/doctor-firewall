#!/usr/bin/env bash
# Bring up the full development stack (with the FMC mock) — offline from vendor/.
#   scripts/dev-up.sh          build + start
#   scripts/dev-up.sh --down   stop (keeps data volumes)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

COMPOSE=(docker compose --project-directory "$INFRA_HOST" -f "$INFRA_HOST/docker-compose.yml"
         -f "$INFRA_HOST/docker-compose.dev.yml" --env-file "$INFRA_HOST/.env")

if [[ "${1:-}" == "--down" ]]; then
    "${COMPOSE[@]}" down
    exit 0
fi

require_vendor
if [[ ! -f "$INFRA/.env" ]]; then
    cp "$INFRA/.env.example" "$INFRA/.env"
    # Development values: local-only bind, dev version tag, dev CA as the FMC trust store.
    sed -i.bak -e 's/^DF_VERSION=.*/DF_VERSION=dev/' \
               -e 's/^DF_HTTPS_BIND=.*/DF_HTTPS_BIND=127.0.0.1/' \
               -e 's/^DF_HTTPS_PORT=.*/DF_HTTPS_PORT=8443/' \
               -e 's|^DF_FMC_CA_FILE=.*|DF_FMC_CA_FILE=./certs/dev-ca.pem|' "$INFRA/.env"
    rm -f "$INFRA/.env.bak"
    ok "created infra/.env for development"
fi

init_secret_dir "$INFRA/secrets" with_mock
docker tag "$REDIS_IMAGE" doctor-firewall/redis:dev
log "Building images (offline)"
"${COMPOSE[@]}" build --quiet
DF_VERSION=dev "$ROOT/scripts/gen-certs.sh" --dev

log "Starting stack"
"${COMPOSE[@]}" up -d --wait
ok "UI: https://localhost:8443  (FMC mock reachable from the stack as fmc-mock:443)"
cat <<EOF

First admin (prompts for a password; you must change it at first login):
  docker compose --project-directory infra -f infra/docker-compose.yml -f infra/docker-compose.dev.yml \\
      exec api python -m app.cli create-user admin --role admin
FMC mock API user: api_user  — password: infra/secrets/fmc_mock_password
EOF
