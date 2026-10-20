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

# Security exceptions (scripts/lock-exceptions.txt): a later cutoff for one package only, so
# a fix for a known vulnerability is not held back by the age floor.
EXCEPTIONS=()
while read -r pkg date advisory _reason; do
    [[ -z "$pkg" || "${pkg:0:1}" == "#" ]] && continue
    [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && -n "$advisory" ]] || die "bad line in lock-exceptions.txt: $pkg"
    EXCEPTIONS+=(--exclude-newer-package "$pkg=$date" --upgrade-package "$pkg")
    log "age-floor exception: $pkg up to $date ($advisory)"
done < "$ROOT/scripts/lock-exceptions.txt"

for req in backend/requirements backend/requirements-dev fmc-mock/requirements; do
    "$PYTHON" -m uv pip compile --quiet --universal --python-version 3.12 --generate-hashes \
        --exclude-newer "$CUTOFF" "${EXCEPTIONS[@]}" --no-header "$ROOT_HOST/$req.in" -o "$ROOT_HOST/$req.txt"
    ok "$req.txt"
done

docker run --rm -v "$ROOT_HOST/frontend:/src" -w /src "$NODE_IMAGE" \
    npm install --package-lock-only --no-audit --no-fund --loglevel=error
ok "frontend/package-lock.json"
log "Now run scripts/vendor.sh to refresh vendor/ for offline builds"
