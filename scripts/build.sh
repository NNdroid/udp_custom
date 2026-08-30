#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${PROJECT_ROOT}/bin"
mkdir -p "${BIN_DIR}"

APP_NAME="udp_custom"
VERSION="1.1.0"

LDFLAGS="-s -w"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "linux/386"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
  "windows/386"
)

echo "=== Building ${APP_NAME} v${VERSION} ==="

for PLATFORM in "${PLATFORMS[@]}"; do
  GOOS="${PLATFORM%/*}"
  GOARCH="${PLATFORM#*/}"
  
  OUTPUT="${BIN_DIR}/${APP_NAME}_${GOOS}_${GOARCH}"
  if [ "${GOOS}" == "windows" ]; then
    OUTPUT="${OUTPUT}.exe"
  fi
  
  echo "--> Compiling ${GOOS}/${GOARCH}..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -ldflags "${LDFLAGS}" -o "${OUTPUT}" "${PROJECT_ROOT}"
done

echo "=== Build Complete! Artifacts in ${BIN_DIR} ==="
