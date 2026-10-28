# Shared helpers for the POSIX scripts (sourced, not executed).
# Works on Linux and on Windows Git Bash (Docker Desktop).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA="$ROOT/infra"
VENDOR="$ROOT/vendor"
# Git Bash would otherwise rewrite "/run/secrets/..." style arguments into Windows paths.
export MSYS_NO_PATHCONV=1

# Pinned third-party images (multi-arch index digests). Keep in sync with Dockerfiles/compose.
PYTHON_IMAGE="python:3.12.16-slim-bookworm@sha256:6dd8b6dab6b3adc7812bab69eca5dbdc1a5cc690ad28306d234ffb4ef8ac9753"
NODE_IMAGE="node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392"
NGINX_IMAGE="nginxinc/nginx-unprivileged:1.30.6-alpine-slim@sha256:5d8bb9437d74a600ec5dbf90c035451c724dc33eac8d3a71078f6f8612c345f6"
POSTGRES_IMAGE="postgres:16.15-bookworm@sha256:e8a07d2c7579b038938cdba6c539e580e5001caf9ea203d397b5cc83e76bd938"
REDIS_IMAGE="redis:7.4.12-bookworm@sha256:b6b6e3dc0c0952737748e55d5d885272840c7e42ba41ab1d5489f693419882f5"
TRIVY_IMAGE="aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
# Local plain tags for third-party images used at runtime on the offline server.
# `docker load` does not reliably keep repo digests, so compose/scripts there refer to
# these tags (created from the digest-pinned images) instead of name@digest.
TRIVY_LOCAL="doctor-firewall/trivy:0.76.0"
BASE_IMAGES=("$PYTHON_IMAGE" "$NODE_IMAGE" "$NGINX_IMAGE" "$POSTGRES_IMAGE" "$REDIS_IMAGE" "$TRIVY_IMAGE")

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

is_windows() { case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) return 0;; *) return 1;; esac; }

# Path form that `docker run -v` accepts on this host.
host_path() {
    if is_windows; then (cd "$1" && pwd -W); else (cd "$1" && pwd); fi
}

# Python interpreter name ("python3" on Linux; "python" with the Windows installer,
# where "python3" may be the Store stub).
if is_windows; then PYTHON="python"; else PYTHON="python3"; fi

# Null device for native Windows tools (curl) when path conversion is disabled.
if is_windows; then NULL_DEV="NUL"; else NULL_DEV="/dev/null"; fi

# Paths in the form the docker CLI understands on this host (C:/... on Windows).
ROOT_HOST="$(host_path "$ROOT")"
INFRA_HOST="$ROOT_HOST/infra"

# On Linux, run helper containers as the invoking user so files they write are ours.
docker_user_args() {
    if is_windows; then echo ""; else echo "--user $(id -u):$(id -g)"; fi
}

random_secret() {
    # 40 chars from a 256-bit random value, URL/SQL/shell-safe alphabet.
    head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-40
}

random_key_b64() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }

# write_secret <file> <value>: create once, never overwrite.
write_secret() {
    local file="$1" value="$2"
    if [[ -s "$file" ]]; then return 0; fi
    (umask 077 && printf '%s' "$value" > "$file")
    # Readable inside containers (bind-mounted file), protected on the host by the
    # directory mode (0700) — see docs/security.md.
    chmod 0644 "$file"
}

# init_secret_dir <dir> [with_mock]
init_secret_dir() {
    local dir="$1" with_mock="${2:-}"
    mkdir -p "$dir"
    chmod 0700 "$dir"
    write_secret "$dir/db_admin_password" "$(random_secret)"
    write_secret "$dir/db_owner_password" "$(random_secret)"
    write_secret "$dir/db_app_password"   "$(random_secret)"
    write_secret "$dir/redis_password"    "$(random_secret)"
    local kid; kid="k$(date -u +%Y%m%d)"
    write_secret "$dir/master_keyring" \
        "{\"active\": \"$kid\", \"keys\": {\"$kid\": \"$(random_key_b64)\"}}"
    if [[ -n "$with_mock" ]]; then
        write_secret "$dir/fmc_mock_password" "$(random_secret)"
    fi
    # Directory sign-in secrets are provided by the administrator (docs/authentication.md);
    # empty placeholders keep compose happy while LDAP / TACACS+ are not used.
    write_secret "$dir/ldap_bind_password" ""
    write_secret "$dir/tacacs_secret" ""
}

require_vendor() {
    [[ -d "$VENDOR/wheels" && -n "$(ls -A "$VENDOR/wheels" 2>/dev/null)" ]] \
        || die "vendor/wheels is empty — run scripts/vendor.sh first (needs internet, dev only)"
    [[ -d "$VENDOR/npm-cache" ]] \
        || die "vendor/npm-cache is missing — run scripts/vendor.sh first"
}

# Runtime images are built locally as doctor-firewall/<component>:<version>. Published to a
# registry they are tags of ONE repository: <repo>:<component>-<version>
# (e.g. haim1418/doctor-firewall:api-0.5.0). See docs/operations.md.
RUNTIME_COMPONENTS=(api web postgres redis)

valid_image_repo() {
    [[ "$1" =~ ^([a-z0-9.-]+(:[0-9]+)?/)?[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)+$ ]]
}

registry_image() {  # registry_image <repo> <component> <version>
    printf '%s:%s-%s' "$1" "$2" "$3"
}

# build_runtime_images <prefix> <version> <git sha>
build_runtime_images() {
    local prefix="$1" version="$2" sha="$3"
    local labels=(--label "org.opencontainers.image.version=$version" --label "org.opencontainers.image.revision=$sha"
                  --label "org.opencontainers.image.source=https://github.com/haimskira/doctor-firewall")
    docker build -q -f "$INFRA_HOST/docker/backend.Dockerfile" --target runtime "${labels[@]}" \
        -t "${prefix}api:$version" "$ROOT_HOST" >/dev/null
    docker build -q -f "$INFRA_HOST/docker/web.Dockerfile" --target runtime "${labels[@]}" \
        -t "${prefix}web:$version" "$ROOT_HOST" >/dev/null
    docker build -q -f "$INFRA_HOST/docker/postgres.Dockerfile" "${labels[@]}" \
        -t "${prefix}postgres:$version" "$ROOT_HOST" >/dev/null
    docker tag "$REDIS_IMAGE" "${prefix}redis:$version"
}

# scan_runtime_images <prefix> <version> — Trivy with the vendored DB; fixable
# HIGH/CRITICAL findings fail.
scan_runtime_images() {
    local prefix="$1" version="$2" component image
    [[ -d "$VENDOR/trivy-cache/db" ]] || die "vendor/trivy-cache missing — run scripts/vendor.sh"
    docker tag "$TRIVY_IMAGE" "$TRIVY_LOCAL"
    for component in "${RUNTIME_COMPONENTS[@]}"; do
        image="${prefix}${component}:$version"
        # Writable tmpfs cache with the vulnerability DB mounted read-only inside it.
        docker save "$image" | docker run --rm -i --tmpfs /cache \
            -v "$(host_path "$VENDOR/trivy-cache/db"):/cache/db:ro" \
            --entrypoint sh "$TRIVY_IMAGE" -c 'cat > /tmp/i.tar && trivy image --input /tmp/i.tar \
                --cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan --quiet \
                --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1' \
            || die "scan failed or fixable HIGH/CRITICAL vulnerabilities in $image (see output above)"
        ok "$image"
    done
}

# ---- offline bundles (scripts/make-bundle.sh, scripts/export-images.sh) ----

# write_source_archive <out.tar.gz> <commit> — the code at HEAD plus .df-commit, so the
# offline server needs no git (and no network) to know which commit it runs.
write_source_archive() {
    local out="$1" sha="$2" tmp
    tmp="$(mktemp -d)"
    git -C "$ROOT_HOST" archive --format=tar HEAD > "$tmp/source.tar"
    printf '%s\n' "$sha" > "$tmp/.df-commit"
    tar -rf "$tmp/source.tar" -C "$tmp" .df-commit
    gzip -6 -c "$tmp/source.tar" > "$out"
    rm -rf "$tmp"
}

# write_bundle_manifest <dir> <version> <commit> <trivy db date> <origin> <image...>
write_bundle_manifest() {
    local dir="$1" version="$2" sha="$3" trivy_date="$4" origin="$5"
    shift 5
    "$PYTHON" - "$(host_path "$dir")/manifest.json" "$version" "$sha" "$trivy_date" "$origin" "$@" <<'PY'
import datetime, json, subprocess, sys
out, version, sha, trivy_date, origin, *images = sys.argv[1:]
ids = {img: subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", img],
                           capture_output=True, text=True, check=True).stdout.strip() for img in images}
json.dump({"version": version, "git_commit": sha, "origin": origin,
           "created_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
           "images": ids, "trivy_db_downloaded_at": trivy_date}, open(out, "w"), indent=2)
PY
}

# seal_bundle <name> — checksums inside, tar, checksum of the tar, clean up.
seal_bundle() {
    local name="$1" out="$ROOT/dist/$1"
    (cd "$out" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
    tar -C "$ROOT/dist" -cf "$ROOT/dist/$name.tar" "$name"
    (cd "$ROOT/dist" && sha256sum "$name.tar" > "$name.tar.sha256")
    rm -rf "$out"
    ok "dist/$name.tar ($(du -h "$ROOT/dist/$name.tar" | cut -f1))"
    ok "dist/$name.tar.sha256"
    log "Carry both files to the offline server — see docs/operations.md (offline server)"
}
