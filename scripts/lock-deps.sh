#!/usr/bin/env bash
# Re-lock Python dependencies with hashes (development machine, needs internet + uv).
# Edit backend/requirements*.in or fmc-mock/requirements.in, then run this, then
# scripts/vendor.sh. The resolver only accepts releases older than 14 days
# (--exclude-newer), so a freshly published (possibly hijacked) release is never picked up.
# Frontend: edit frontend/package.json (exact versions) and regenerate the lock inside
# the pinned Node image, as below.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v "$PYTHON" >/dev/null || die "$PYTHON is required"
"$PYTHON" -m uv --version >/dev/null 2>&1 || die "uv is required: $PYTHON -m pip install --user uv"
CUTOFF="$("$PYTHON" -c 'import datetime as d; print((d.date.today()-d.timedelta(days=14)).isoformat())')"

for req in backend/requirements backend/requirements-dev fmc-mock/requirements; do
    "$PYTHON" -m uv pip compile --quiet --universal --python-version 3.12 --generate-hashes \
        --exclude-newer "$CUTOFF" --no-header "$ROOT/$req.in" -o "$ROOT/$req.txt"
    ok "$req.txt"
done

docker run --rm -v "$ROOT_HOST/frontend:/src" -w /src "$NODE_IMAGE" \
    npm install --package-lock-only --no-audit --no-fund --loglevel=error
ok "frontend/package-lock.json"
log "Now run scripts/vendor.sh to refresh vendor/ for offline builds"
