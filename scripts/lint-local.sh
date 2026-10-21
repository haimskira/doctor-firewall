#!/usr/bin/env bash
# Dev helper: format, lint and type-check the working tree inside the CI test image
# (no rebuild needed). Fixes are written back into backend/ and fmc-mock/.
# CI itself (scripts/ci.sh) only checks and never rewrites files.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
docker run --rm -u 0 \
  -v "$ROOT_HOST/backend/app:/srv/app" \
  -v "$ROOT_HOST/backend/tests:/srv/tests" \
  -v "$ROOT_HOST/backend/alembic:/srv/alembic" \
  -v "$ROOT_HOST/backend/pyproject.toml:/srv/pyproject.toml:ro" \
  -v "$ROOT_HOST/fmc-mock:/srv/fmc-mock" \
  doctor-firewall/api-test:ci sh -c '
    set -e
    ruff format app tests alembic
    ruff check --fix app tests alembic
    mypy app tests alembic
    bandit -q -r app -c pyproject.toml
    cd /srv/fmc-mock && ruff format . && ruff check --fix . && mypy fmc_mock tests
  '
