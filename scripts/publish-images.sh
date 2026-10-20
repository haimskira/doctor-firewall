#!/usr/bin/env bash
# Build, scan and push the runtime images to a registry (Docker Hub by default).
# Development machine; run `docker login` yourself first — no credentials are stored.
#
#   DF_IMAGE_PREFIX=myuser/doctor-firewall- scripts/publish-images.sh <x.y.z> [--skip-ci] [--allow-dirty]
#
# Pushes <prefix>api, <prefix>web, <prefix>postgres and <prefix>redis tagged <x.y.z>.
# The images contain the application code (public in this repository) and no secrets:
# passwords, keys and certificates are mounted at runtime from infra/secrets and infra/certs.
# Production pulls them with scripts/install-online.sh (docs/operations.md).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="${1:-}"; shift || true
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)?$ ]] \
    || die "usage: DF_IMAGE_PREFIX=<user>/doctor-firewall- publish-images.sh <x.y.z> [--skip-ci] [--allow-dirty]"
SKIP_CI=""; ALLOW_DIRTY=""
for arg in "$@"; do
    case "$arg" in --skip-ci) SKIP_CI=1;; --allow-dirty) ALLOW_DIRTY=1;; *) die "unknown option $arg";; esac
done
PREFIX="${DF_IMAGE_PREFIX:-}"
valid_image_prefix "$PREFIX" \
    || die "set DF_IMAGE_PREFIX, e.g. DF_IMAGE_PREFIX=myuser/doctor-firewall- (lowercase, ends with - / . or _)"

require_vendor
if [[ -z "$ALLOW_DIRTY" ]] && ! git -C "$ROOT_HOST" diff --quiet HEAD --; then
    die "working tree has uncommitted changes — commit first (or --allow-dirty for a test push)"
fi
SHA="$(git -C "$ROOT_HOST" rev-parse --short=12 HEAD)"

if [[ -z "$SKIP_CI" ]]; then
    log "Running the CI gate first"
    "$ROOT/scripts/ci.sh"
fi

log "Building runtime images ${PREFIX}*:$VERSION (commit $SHA)"
build_runtime_images "$PREFIX" "$VERSION" "$SHA"
ok "images built"

log "Scanning (Trivy, fixable HIGH/CRITICAL block the push)"
scan_runtime_images "$PREFIX" "$VERSION"

log "Pushing"
for component in "${RUNTIME_COMPONENTS[@]}"; do
    image="${PREFIX}${component}:$VERSION"
    docker push -q "$image" >/dev/null || die "push failed for $image — are you logged in (docker login)?"
    digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "?")"
    ok "$image  ($digest)"
done

cat <<EOF

Published Doctor Firewall $VERSION (commit $SHA). On the production server (root, repo checkout):
  git fetch && git checkout $SHA
  DF_IMAGE_PREFIX=$PREFIX scripts/install-online.sh $VERSION
EOF
