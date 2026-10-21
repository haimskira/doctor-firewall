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
build_runtime_images "doctor-firewall/" "$VERSION" "$SHA"
docker tag "$TRIVY_IMAGE" "$TRIVY_LOCAL"
ok "images built"

log "Scanning runtime images offline (Trivy, fixable HIGH/CRITICAL fail the bundle)"
scan_runtime_images "doctor-firewall/" "$VERSION"

log "Writing bundle to dist/$NAME"
rm -rf "$OUT"; mkdir -p "$OUT/vendor"
# Plain tags only: they survive `docker load` on any image store.
IMAGES=("doctor-firewall/api:$VERSION" "doctor-firewall/web:$VERSION" "doctor-firewall/postgres:$VERSION"
        "doctor-firewall/redis:$VERSION" "$TRIVY_LOCAL")
docker save "${IMAGES[@]}" | gzip -6 > "$OUT/images.tar.gz"
cp -r "$VENDOR/wheels" "$VENDOR/npm-cache" "$VENDOR/trivy-cache" "$OUT/vendor/"

write_source_archive "$OUT/source.tar.gz" "$SHA"
write_bundle_manifest "$OUT" "$VERSION" "$SHA" "$(cat "$VENDOR/trivy-cache/DOWNLOADED_AT" 2>/dev/null || echo unknown)" "build:$SHA" "${IMAGES[@]}"
seal_bundle "$NAME"
