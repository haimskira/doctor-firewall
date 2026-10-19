# Shared helpers for the POSIX scripts (sourced, not executed).
# Works on Linux and on Windows Git Bash (Docker Desktop).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA="$ROOT/infra"
VENDOR="$ROOT/vendor"
# Git Bash would otherwise rewrite "/run/secrets/..." style arguments into Windows paths.
export MSYS_NO_PATHCONV=1

# Pinned third-party images (multi-arch index digests). Keep in sync with Dockerfiles/compose.
PYTHON_IMAGE="python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
NODE_IMAGE="node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392"
NGINX_IMAGE="nginxinc/nginx-unprivileged:1.30.6-alpine-slim@sha256:5d8bb9437d74a600ec5dbf90c035451c724dc33eac8d3a71078f6f8612c345f6"
POSTGRES_IMAGE="postgres:16.15-bookworm@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4"
REDIS_IMAGE="redis:7.4.11-bookworm@sha256:4fa24486b8bcca8eec45ee0eb166edc674795e53a2b53d1a9ef263eecebaac85"
TRIVY_IMAGE="aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
BASE_IMAGES=("$PYTHON_IMAGE" "$NODE_IMAGE" "$NGINX_IMAGE" "$POSTGRES_IMAGE" "$REDIS_IMAGE" "$TRIVY_IMAGE")

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

is_windows() { case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) return 0;; *) return 1;; esac; }

# Path form that `docker run -v` accepts on this host.
host_path() {
    if is_windows; then (cd "$1" && pwd -W); else (cd "$1" && pwd); fi
}

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
}

require_vendor() {
    [[ -d "$VENDOR/wheels" && -n "$(ls -A "$VENDOR/wheels" 2>/dev/null)" ]] \
        || die "vendor/wheels is empty — run scripts/vendor.sh first (needs internet, dev only)"
    [[ -d "$VENDOR/npm-cache" ]] \
        || die "vendor/npm-cache is missing — run scripts/vendor.sh first"
}
