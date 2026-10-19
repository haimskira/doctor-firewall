#!/usr/bin/env bash
# Offline dependency/vulnerability scan on the production server (no internet):
# lock files in this checkout + the running images, with the Trivy DB from the bundle.
# Exit code 1 on findings. The DB date is printed so stale data is visible.
#   scripts/scan-offline.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CACHE="$VENDOR/trivy-cache"
[[ -d "$CACHE/db" ]] || die "no Trivy DB in vendor/trivy-cache — install an offline bundle first"
log "Trivy DB downloaded at: $(cat "$CACHE/DOWNLOADED_AT" 2>/dev/null || echo unknown)"

VERSION="$(grep -E '^DF_VERSION=' "$INFRA/.env" | cut -d= -f2-)"
# Writable tmpfs cache with the vulnerability DB mounted read-only inside it.
TRIVY=(docker run --rm --tmpfs /cache -v "$(host_path "$CACHE/db"):/cache/db:ro")
COMMON=(--cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan --quiet --scanners vuln --exit-code 1)

log "Lock files (requirements*.txt, package-lock.json)"
"${TRIVY[@]}" -v "$ROOT_HOST:/repo:ro" "$TRIVY_IMAGE" fs "${COMMON[@]}" \
    --skip-dirs /repo/vendor --skip-dirs /repo/frontend/node_modules /repo
ok "no known vulnerable dependencies"

log "Images (fixable HIGH/CRITICAL)"
for image in "doctor-firewall/api:$VERSION" "doctor-firewall/web:$VERSION" "doctor-firewall/postgres:$VERSION" "$REDIS_IMAGE"; do
    docker save "$image" | "${TRIVY[@]}" -i --entrypoint sh "$TRIVY_IMAGE" -c \
        "cat > /tmp/i.tar && trivy image --input /tmp/i.tar ${COMMON[*]} --ignore-unfixed --severity HIGH,CRITICAL"
    ok "$image"
done
