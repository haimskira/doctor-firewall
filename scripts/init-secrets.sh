#!/usr/bin/env bash
# Create infra/secrets/* once (random values). Existing files are never overwritten.
#
#   scripts/init-secrets.sh          # production secrets
#   scripts/init-secrets.sh --dev    # + the FMC mock's API password (development only)
#
# Directory 0700 (owner only); files 0644 so the unprivileged container users can read
# them through the per-file Docker secret mounts. Run as root on the production host.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WITH_MOCK=""
[[ "${1:-}" == "--dev" ]] && WITH_MOCK=1

init_secret_dir "$INFRA/secrets" $WITH_MOCK
ok "secrets present in infra/secrets (values are never printed)"
ls -1 "$INFRA/secrets"
