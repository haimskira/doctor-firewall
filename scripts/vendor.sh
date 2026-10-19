#!/usr/bin/env bash
# Populate vendor/ — the ONLY step that uses the internet (development machine).
#
#   vendor/wheels/       every Python wheel in the hash-locked requirements (Linux, cp312)
#   vendor/npm-cache/    npm cache for the locked frontend deps (Linux-native binaries)
#   vendor/trivy-cache/  Trivy vulnerability DB for offline SCA (dated, see manifest)
#   base images          pulled by pinned digest into the local Docker image store
#
# After this, every build and test runs with no network access.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "Pulling pinned base images"
for image in "${BASE_IMAGES[@]}"; do
    docker pull -q "$image" >/dev/null
    ok "$image"
done

log "Downloading Python wheels (Linux, hash-verified)"
mkdir -p "$VENDOR/wheels"
docker run --rm -v "$ROOT_HOST/backend:/req:ro" -v "$ROOT_HOST/fmc-mock:/mreq:ro" \
    -v "$(host_path "$VENDOR/wheels"):/out" "$PYTHON_IMAGE" sh -c '
  set -e
  export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore
  pip download -q --only-binary=:all: --require-hashes -r /req/requirements.txt -r /req/requirements-dev.txt -d /out
  pip download -q --only-binary=:all: --require-hashes -r /mreq/requirements.txt -d /out
'
ok "$(find "$VENDOR/wheels" -name '*.whl' | wc -l | tr -d ' ') wheels"

log "Populating npm cache (inside Linux so platform binaries match production)"
mkdir -p "$VENDOR/npm-cache"
docker run --rm -v "$ROOT_HOST/frontend:/src:ro" -v "$(host_path "$VENDOR/npm-cache"):/npm-cache" \
    "$NODE_IMAGE" sh -c '
  set -e
  mkdir -p /tmp/w && cp /src/package.json /src/package-lock.json /src/.npmrc /tmp/w/
  cd /tmp/w && npm ci --cache /npm-cache --no-audit --no-fund --loglevel=error
'
ok "npm cache ready"

log "Downloading Trivy vulnerability DB"
mkdir -p "$VENDOR/trivy-cache"
docker run --rm -v "$(host_path "$VENDOR/trivy-cache"):/cache" "$TRIVY_IMAGE" \
    image --download-db-only --cache-dir /cache --quiet
date -u +%Y-%m-%dT%H:%M:%SZ > "$VENDOR/trivy-cache/DOWNLOADED_AT"
ok "Trivy DB downloaded $(cat "$VENDOR/trivy-cache/DOWNLOADED_AT")"

log "vendor/ is complete — builds and CI now work offline"
