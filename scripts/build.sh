#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${PROJECT_ROOT}/bin"
APP_NAME="udp_custom"

# Supply VERSION to reproduce a Release build. Otherwise use the release version
# convention with the current UTC date and the latest commit's short hash.
if [ -z "${VERSION:-}" ]; then
  VERSION="v1.0.$(date -u +%Y%m%d)-$(git -C "${PROJECT_ROOT}" rev-parse --short=7 HEAD)"
fi
if ! [[ "${VERSION}" =~ ^v1\.0\.[0-9]{8}-[0-9a-f]{7}$ ]]; then
  echo "VERSION must be v1.0.yyyyMMdd-<7-character-git-hash>; got: ${VERSION}" >&2
  exit 1
fi

mkdir -p "${BIN_DIR}"
LDFLAGS="-s -w -X main.Version=${VERSION}"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm/v7"
  "linux/386"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
  "windows/386"
)

echo "=== Building ${APP_NAME} ${VERSION} ==="

for PLATFORM in "${PLATFORMS[@]}"; do
  IFS=/ read -r GOOS GOARCH GOARM <<< "${PLATFORM}"
  OUTPUT="${BIN_DIR}/${APP_NAME}_${GOOS}_${GOARCH}"
  [ "${GOOS}" = "windows" ] && OUTPUT="${OUTPUT}.exe"

  echo "--> Compiling ${PLATFORM}..."
  if [ -n "${GOARM:-}" ]; then
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" GOARM="${GOARM#v}" \
      go build -trimpath -ldflags "${LDFLAGS}" -o "${OUTPUT}" "${PROJECT_ROOT}"
  else
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
      go build -trimpath -ldflags "${LDFLAGS}" -o "${OUTPUT}" "${PROJECT_ROOT}"
  fi
done

echo "=== Build complete. Raw binaries: ${BIN_DIR} ==="
