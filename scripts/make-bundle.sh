#!/usr/bin/env bash
# Build the offline production bundle (development machine).
#
#   scripts/make-bundle.sh <version> [--skip-ci] [--allow-dirty]
#
# Produces dist/doctor-firewall-bundle-<version>-<gitsha>.tar (+ .sha256), containing:
#   images.tar.gz   api, web, postgres, redis, trivy (docker save)
#   vendor/         wheels, npm cache, Trivy DB  (audit trail + offline scanning)
#   manifest.json   version, commit, image ids, Trivy DB date
#   SHA256SUMS      checksums of everything above
#
# The bundle is NOT committed to Git (too large). Transfer it to the server on approved
# media / scp; the server gets code + compose through `git pull` and verifies that the
# bundle was built from exactly that commit (scripts/install-offline.sh).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="${1:-}"; shift || true
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)?$ ]] || die "usage: make-bundle.sh <x.y.z> [--skip-ci] [--allow-dirty]"
SKIP_CI=""; ALLOW_DIRTY=""
for arg in "$@"; do
    case "$arg" in --skip-ci) SKIP_CI=1;; --allow-dirty) ALLOW_DIRTY=1;; *) die "unknown option $arg";; esac
done

require_vendor
[[ -d "$VENDOR/trivy-cache/db" ]] || die "vendor/trivy-cache missing — run scripts/vendor.sh"
if [[ -z "$ALLOW_DIRTY" ]] && ! git -C "$ROOT_HOST" diff --quiet HEAD --; then
    die "working tree has uncommitted changes — commit first (or --allow-dirty for a test bundle)"
fi
SHA="$(git -C "$ROOT_HOST" rev-parse --short=12 HEAD)"
NAME="doctor-firewall-bundle-$VERSION-$SHA"
OUT="$ROOT/dist/$NAME"

if [[ -z "$SKIP_CI" ]]; then
    log "Running the CI gate first"
    "$ROOT/scripts/ci.sh"
fi

log "Building runtime images $VERSION"
docker build -q -f "$INFRA_HOST/docker/backend.Dockerfile" --target runtime \
    --label "org.opencontainers.image.version=$VERSION" --label "org.opencontainers.image.revision=$SHA" \
    -t "doctor-firewall/api:$VERSION" "$ROOT_HOST" >/dev/null
docker build -q -f "$INFRA_HOST/docker/web.Dockerfile" --target runtime \
    --label "org.opencontainers.image.version=$VERSION" --label "org.opencontainers.image.revision=$SHA" \
    -t "doctor-firewall/web:$VERSION" "$ROOT_HOST" >/dev/null
docker build -q -f "$INFRA_HOST/docker/postgres.Dockerfile"     --label "org.opencontainers.image.version=$VERSION" --label "org.opencontainers.image.revision=$SHA"     -t "doctor-firewall/postgres:$VERSION" "$ROOT_HOST" >/dev/null
ok "images built"

log "Scanning runtime images offline (Trivy, fixable HIGH/CRITICAL fail the bundle)"
for image in "doctor-firewall/api:$VERSION" "doctor-firewall/web:$VERSION" "doctor-firewall/postgres:$VERSION" "$REDIS_IMAGE"; do
    # Writable tmpfs cache with the vulnerability DB mounted read-only inside it.
    docker save "$image" | docker run --rm -i --tmpfs /cache \
        -v "$(host_path "$VENDOR/trivy-cache/db"):/cache/db:ro" \
        --entrypoint sh "$TRIVY_IMAGE" -c 'cat > /tmp/i.tar && trivy image --input /tmp/i.tar \
            --cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan --quiet \
            --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1' \
        || die "scan failed or fixable HIGH/CRITICAL vulnerabilities in $image (see output above)"
    ok "$image"
done

log "Writing bundle to dist/$NAME"
rm -rf "$OUT"; mkdir -p "$OUT/vendor"
IMAGES=("doctor-firewall/api:$VERSION" "doctor-firewall/web:$VERSION" "doctor-firewall/postgres:$VERSION" "$REDIS_IMAGE" "$TRIVY_IMAGE")
docker save "${IMAGES[@]}" | gzip -6 > "$OUT/images.tar.gz"
cp -r "$VENDOR/wheels" "$VENDOR/npm-cache" "$VENDOR/trivy-cache" "$OUT/vendor/"

"$PYTHON" - "$ROOT_HOST/dist/$NAME/manifest.json" "$VERSION" "$SHA" "$(cat "$VENDOR/trivy-cache/DOWNLOADED_AT" 2>/dev/null || echo unknown)" "${IMAGES[@]}" <<'PY'
import json, subprocess, sys, datetime
out, version, sha, trivy_date, *images = sys.argv[1:]
ids = {img: subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", img],
                           capture_output=True, text=True, check=True).stdout.strip() for img in images}
json.dump({"version": version, "git_commit": sha,
           "created_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
           "images": ids, "trivy_db_downloaded_at": trivy_date}, open(out, "w"), indent=2)
PY
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
tar -C "$ROOT/dist" -cf "$ROOT/dist/$NAME.tar" "$NAME"
(cd "$ROOT/dist" && sha256sum "$NAME.tar" > "$NAME.tar.sha256")
rm -rf "$OUT"
ok "dist/$NAME.tar ($(du -h "$ROOT/dist/$NAME.tar" | cut -f1))"
ok "dist/$NAME.tar.sha256"
log "Transfer both files to the server, git pull commit $SHA there, then run scripts/install-offline.sh"
