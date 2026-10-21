#!/usr/bin/env bash
# Build the transfer bundle for the OFFLINE production server, from the images published on
# Docker Hub. Runs on a Linux machine WITH internet, from a checkout of the published commit:
#
#   git checkout <commit printed by publish-images>
#   DF_IMAGE_REPO=haim1418/doctor-firewall scripts/export-images.sh <x.y.z>
#
# Produces dist/doctor-firewall-bundle-<ver>-<sha>.tar (+ .sha256) containing
#   images.tar.gz      api, web, postgres, redis (re-tagged to local names) + trivy
#   source.tar.gz      the code at that commit (compose files, scripts, docs) + .df-commit
#   vendor/trivy-cache vulnerability DB for offline scans on the server (dated)
#   manifest.json      version, commit, image ids, DB date; SHA256SUMS of everything
# Carry both files to the offline server and follow docs/operations.md ("offline server").
# After that, nothing on the server needs any network except the FMC.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)?$ ]] \
    || die "usage: DF_IMAGE_REPO=<user>/<repo> export-images.sh <x.y.z>"
REPO="${DF_IMAGE_REPO:-}"
valid_image_repo "$REPO" || die "set DF_IMAGE_REPO (the repository the images were published to)"
git -C "$ROOT_HOST" diff --quiet HEAD -- || die "the checkout has local changes — use a clean checkout of the published commit"
SHA="$(git -C "$ROOT_HOST" rev-parse --short=12 HEAD)"

log "Pulling $REPO:*-$VERSION"
for component in "${RUNTIME_COMPONENTS[@]}"; do
    image="$(registry_image "$REPO" "$component" "$VERSION")"
    docker pull -q "$image" >/dev/null || die "cannot pull $image"
    revision="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")"
    [[ "$revision" == "$SHA" ]] || die "$image was built from $revision but this checkout is $SHA — git checkout $revision"
    # Local names on the offline server: compose needs no registry settings there.
    docker tag "$image" "doctor-firewall/$component:$VERSION"
done
docker pull -q "$TRIVY_IMAGE" >/dev/null
docker tag "$TRIVY_IMAGE" "$TRIVY_LOCAL"
ok "images pulled and verified against commit $SHA"

NAME="doctor-firewall-bundle-$VERSION-$SHA"
OUT="$ROOT/dist/$NAME"
rm -rf "$OUT"; mkdir -p "$OUT/vendor/trivy-cache"

log "Downloading the Trivy vulnerability DB (for offline scans on the server)"
docker run --rm -v "$(host_path "$OUT/vendor/trivy-cache"):/cache" "$TRIVY_IMAGE" \
    image --download-db-only --cache-dir /cache --quiet
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/vendor/trivy-cache/DOWNLOADED_AT"

log "Scanning the images before they leave (fixable HIGH/CRITICAL fail the export)"
VENDOR_SAVED="$VENDOR"; VENDOR="$OUT/vendor"
scan_runtime_images "doctor-firewall/" "$VERSION"
VENDOR="$VENDOR_SAVED"

log "Writing the bundle"
IMAGES=()
for component in "${RUNTIME_COMPONENTS[@]}"; do IMAGES+=("doctor-firewall/$component:$VERSION"); done
IMAGES+=("$TRIVY_LOCAL")
docker save "${IMAGES[@]}" | gzip -6 > "$OUT/images.tar.gz"
write_source_archive "$OUT/source.tar.gz" "$SHA"
write_bundle_manifest "$OUT" "$VERSION" "$SHA" "$(cat "$OUT/vendor/trivy-cache/DOWNLOADED_AT")" "registry:$REPO" "${IMAGES[@]}"
seal_bundle "$NAME"
