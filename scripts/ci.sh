#!/usr/bin/env bash
# Full local CI gate: lint, format, strict typing, SAST, unit + integration tests,
# frontend lint/typecheck/tests, and dependency (SCA) scanning. Any finding fails.
#
#   scripts/ci.sh            # SCA via pip-audit + npm audit (needs internet; dev)
#   scripts/ci.sh --offline  # SCA via Trivy with the DB shipped in vendor/trivy-cache
#
# Everything runs in containers built from vendor/, so Windows and Linux behave the same.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

OFFLINE=""
[[ "${1:-}" == "--offline" ]] && OFFLINE=1

require_vendor
CI_DIR="$INFRA/.ci"
COMPOSE=(docker compose -f "$INFRA_HOST/docker-compose.ci.yml")

cleanup() {
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$CI_DIR"
}
trap cleanup EXIT

log "Building images (offline, from vendor/)"
docker build -q -f "$INFRA_HOST/docker/backend.Dockerfile" --target test -t doctor-firewall/api-test:ci "$ROOT_HOST" >/dev/null
docker build -q -f "$INFRA_HOST/docker/fmc-mock.Dockerfile" -t doctor-firewall/fmc-mock:ci "$ROOT_HOST" >/dev/null
docker build -q -f "$INFRA_HOST/docker/postgres.Dockerfile" -t doctor-firewall/postgres:ci "$ROOT_HOST" >/dev/null
docker build -q -f "$INFRA_HOST/docker/web.Dockerfile" --target test -t doctor-firewall/web-test:ci "$ROOT_HOST" >/dev/null
ok "images built"

log "Backend: ruff, format, mypy --strict, bandit"
docker run --rm doctor-firewall/api-test:ci sh -c '
  set -e
  ruff check app tests alembic
  ruff format --check app tests alembic
  mypy app tests alembic
  bandit -q -r app -c pyproject.toml
  cd /srv/fmc-mock && ruff check . && ruff format --check . && mypy fmc_mock tests
  PYTHONPATH=/srv/fmc-mock pytest -q -p no:cacheprovider tests
'
ok "backend static checks + mock tests"

log "Frontend: eslint, tsc --strict, vitest"
docker run --rm doctor-firewall/web-test:ci
ok "frontend checks"

log "Backend: unit + integration tests (PostgreSQL, Redis, FMC mock over TLS)"
rm -rf "$CI_DIR"
init_secret_dir "$CI_DIR/secrets" with_mock
mkdir -p "$CI_DIR/certs/raw" "$CI_DIR/certs/other" "$CI_DIR/certs/trust" "$CI_DIR/certs/fmc-mock" "$CI_DIR/reports"
# shellcheck disable=SC2046
docker run --rm $(docker_user_args) -v "$(host_path "$CI_DIR/certs/raw"):/out" doctor-firewall/api-test:ci \
    python -m app.tools.certs --out /out --key-mode 0644 --ca-name "DF CI CA" --leaf fmc-mock:fmc-mock >/dev/null
# shellcheck disable=SC2046
docker run --rm $(docker_user_args) -v "$(host_path "$CI_DIR/certs/other"):/out" doctor-firewall/api-test:ci \
    python -m app.tools.certs --out /out --key-mode 0644 --ca-name "Untrusted CA" --leaf x:x >/dev/null
cp "$CI_DIR/certs/raw/ca.pem" "$CI_DIR/certs/trust/ca.pem"
cp "$CI_DIR/certs/other/ca.pem" "$CI_DIR/certs/trust/other-ca.pem"
cp "$CI_DIR/certs/raw/fmc-mock.pem" "$CI_DIR/certs/raw/fmc-mock.key" "$CI_DIR/certs/fmc-mock/"
chmod 0777 "$CI_DIR/reports"
"${COMPOSE[@]}" up --quiet-pull --abort-on-container-exit --exit-code-from tests tests
ok "unit + integration tests"

log "Dependency scan (SCA)"
if [[ -n "$OFFLINE" ]]; then
    [[ -d "$VENDOR/trivy-cache/db" ]] || die "vendor/trivy-cache missing — refresh the offline bundle"
    docker run --rm -v "$(host_path "$VENDOR/trivy-cache"):/cache:ro" -v "$ROOT_HOST:/repo:ro" \
        "$TRIVY_IMAGE" fs --cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan \
        --scanners vuln --exit-code 1 --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
        --skip-dirs /repo/vendor --skip-dirs /repo/frontend/node_modules /repo
else
    docker run --rm doctor-firewall/api-test:ci sh -c \
        'pip-audit --strict --progress-spinner off --cache-dir /tmp/pip-audit --disable-pip --require-hashes -r requirements.txt -r requirements-dev.txt'
    docker run --rm -v "$(host_path "$ROOT/frontend"):/src:ro" -w /src "$NODE_IMAGE" \
        npm audit --audit-level=low --package-lock-only
fi
ok "no known vulnerable dependencies"

log "CI PASSED"
