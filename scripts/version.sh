#!/bin/bash
# Print the udp_custom release version, derived purely from git metadata so the
# same rule is used by local builds (build.sh / install.sh) and the CI release
# workflow. Format:
#
#   v1.0.yyyyMMdd.<git-commit-count>-<short-sha>
#
#   yyyyMMdd           current UTC date (date -u +%Y%m%d)
#   git-commit-count   total commits reachable from HEAD (git rev-list --count HEAD)
#   short-sha          first 7 hex chars of HEAD (git rev-parse --short=7)
#
# Falls back to "v1.0.<date>.0-local" when run outside a git work tree
# (e.g. from a source tarball), so local dev builds still produce a sane string.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATE="$(date -u +%Y%m%d)"

# Resolve the version from inside the repo root so plain "git" (no -C) is used;
# some sandboxed environments intercept "git -C <path>" while leaving "git" alone.
if ( cd "${ROOT}" && git rev-parse >/dev/null 2>&1 ); then
  COUNT="$(cd "${ROOT}" && git rev-list --count HEAD)"
  SHA="$(cd "${ROOT}" && git rev-parse --short=7 HEAD)"
else
  COUNT=0
  SHA=local
fi

echo "v1.0.${DATE}.${COUNT}-${SHA}"
