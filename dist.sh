#!/usr/bin/env bash

set -o errexit

BINARY=${BINARY:-}
VERSION=${VERSION:-}

if [[ -z "$BINARY" ]] || [[ -z "$VERSION" ]]; then
  echo "Missing required environment variable: BINARY and VERSION"
  echo "Usage: BINARY=<binary-name> VERSION=<version-number> $0"
  exit 1
fi

ARCHS=(darwin-amd64 linux-amd64 linux-arm64 linux-ppc64le linux-armv6 freebsd-amd64 windows-amd64)
RELEASE_DIR="release"
mkdir -p "$RELEASE_DIR"

for ARCH in "${ARCHS[@]}"; do
  ARCH_DIR="$RELEASE_DIR/${BINARY}-${VERSION}.${ARCH}"
  mkdir -p "$ARCH_DIR"

  GO_OS=$(echo "$ARCH" | awk -F- '{print $1}')
  GO_ARCH=$(echo "$ARCH" | awk -F- '{print $2}')

  CGO_ENABLED=0 GO111MODULE=on GOOS="$GO_OS" GOARCH="$GO_ARCH" \
    go build -ldflags="-X main.VERSION=$VERSION" \
    -o "$ARCH_DIR/$BINARY" .

  cd "$RELEASE_DIR"
  sha256sum "${BINARY}-${VERSION}.${ARCH}/$BINARY" > "${BINARY}-${VERSION}.${ARCH}-sha256sum.txt"
  tar -czvf "${BINARY}-${VERSION}.${ARCH}.tar.gz" "${BINARY}-${VERSION}.${ARCH}"
  cd ..
done
