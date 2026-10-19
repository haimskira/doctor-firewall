#!/usr/bin/env bash
# Enable the repository's Git hooks (.githooks/):
#   pre-commit: blocks secrets-looking files and large/binary artefacts (bundles, wheels, images)
#   pre-push:   runs the full CI gate (scripts/ci.sh); push is refused if it fails
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
git -C "$ROOT" config core.hooksPath .githooks
ok "git hooks enabled (core.hooksPath=.githooks)"
