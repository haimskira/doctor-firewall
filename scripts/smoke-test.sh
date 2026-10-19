#!/usr/bin/env bash
# End-to-end smoke test of a running DEV stack (scripts/dev-up.sh), through nginx over
# HTTPS with full certificate verification against the dev CA:
#   bootstrap admin (CLI) -> login -> forced password change -> CSRF-protected calls ->
#   create FMC connection -> read-only connection test against the FMC mock (TLS) ->
#   audit chain verification.
# Uses a throw-away admin account "smoke-<random>".
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BASE="https://localhost:${DF_HTTPS_PORT:-8443}"
CA="$INFRA_HOST/certs/dev-ca.pem"
COMPOSE=(docker compose --project-directory "$INFRA_HOST" -f "$INFRA_HOST/docker-compose.yml"
         -f "$INFRA_HOST/docker-compose.dev.yml" --env-file "$INFRA_HOST/.env")
[[ -s "$INFRA/certs/dev-ca.pem" ]] || die "dev CA not found — run scripts/dev-up.sh first"

JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
USER_NAME="smoke-$(random_secret | cut -c1-6 | tr 'A-Z' 'a-z')"
TEMP_PW="Tmp-$(random_secret | cut -c1-16)-1a"
NEW_PW="New-$(random_secret | cut -c1-16)-2b"

json_field() { python -c "import json,sys; print(json.load(sys.stdin)$1)"; }
call() {  # call METHOD PATH [JSON] -> body on stdout; fails on HTTP >= 400
    local method="$1" path="$2" data="${3:-}"
    local args=(--silent --show-error --fail-with-body --cacert "$CA" -b "$JAR" -c "$JAR"
                -X "$method" -H "Accept: application/json")
    [[ -n "${CSRF:-}" ]] && args+=(-H "X-CSRF-Token: $CSRF")
    [[ -n "$data" ]] && args+=(-H "Content-Type: application/json" --data "$data")
    curl "${args[@]}" "$BASE$path"
}

log "TLS + security headers"
headers="$(curl --silent --show-error --cacert "$CA" -D - -o "$NULL_DEV" "$BASE/")"
for h in content-security-policy strict-transport-security x-frame-options x-content-type-options; do
    grep -qi "^$h:" <<<"$headers" || die "missing header $h"
done
ok "UI served over verified TLS with security headers"

log "Bootstrap admin via CLI"
printf '%s\n' "$TEMP_PW" | "${COMPOSE[@]}" exec -T api \
    python -m app.cli create-user "$USER_NAME" --role admin --password-stdin >/dev/null
ok "created $USER_NAME"

log "Login + forced password change"
CSRF="$(call POST /api/auth/login "{\"username\":\"$USER_NAME\",\"password\":\"$TEMP_PW\"}" | json_field "['csrf_token']")"
code="$(curl --silent --cacert "$CA" -b "$JAR" -o "$NULL_DEV" -w '%{http_code}' "$BASE/api/users")"
[[ "$code" == "403" ]] || die "expected 403 before password change, got $code"
CSRF="$(call POST /api/auth/change-password "{\"current_password\":\"$TEMP_PW\",\"new_password\":\"$NEW_PW\"}" | json_field "['csrf_token']")"
call GET /api/users >/dev/null
ok "password changed; admin endpoints reachable"

log "CSRF enforcement"
code="$(curl --silent --cacert "$CA" -b "$JAR" -o "$NULL_DEV" -w '%{http_code}' -X PATCH \
        -H 'Content-Type: application/json' --data '{"language":"en"}' "$BASE/api/me/preferences")"
[[ "$code" == "403" ]] || die "state change without CSRF token returned $code"
ok "request without CSRF token rejected"

log "FMC connection (read-only test against the mock over TLS)"
MOCK_PW="$(cat "$INFRA/secrets/fmc_mock_password")"
conn_id="$(call POST /api/fmc/connections \
    "{\"name\":\"$USER_NAME\",\"host\":\"fmc-mock\",\"port\":443,\"username\":\"api_user\",\"password\":\"$MOCK_PW\"}" \
    | json_field "['id']")"
result="$(call POST "/api/fmc/connections/$conn_id/test")"
[[ "$(json_field "['ok']" <<<"$result")" == "True" ]] || die "FMC test failed: $result"
ok "FMC $(json_field "['server_version']" <<<"$result"), domain $(json_field "['domain_uuid']" <<<"$result")"
call DELETE "/api/fmc/connections/$conn_id" >/dev/null

log "Audit chain"
verify="$(call POST /api/audit/verify)"
[[ "$(json_field "['ok']" <<<"$verify")" == "True" ]] || die "audit chain broken: $verify"
ok "audit chain intact ($(json_field "['checked']" <<<"$verify") records)"

log "Deactivate smoke account"
uid="$(call GET /api/users | python -c "import json,sys; print([u['id'] for u in json.load(sys.stdin) if u['username']=='$USER_NAME'][0])")"
# The account is the caller itself; deactivation is refused if it is the last admin.
call PATCH "/api/users/$uid" '{"is_active": false}' >/dev/null 2>&1 \
    || log "kept $USER_NAME active (last administrator) — deactivate it after creating your own admin"
log "SMOKE TEST PASSED"
