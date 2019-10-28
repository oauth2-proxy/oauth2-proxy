#!/usr/bin/env bash

set -o errexit

if [[ -z ${BINARY} ]] || [[ -z ${VERSION} ]]; then
	echo "Missing required env var: BINARY=X VERSION=X $(basename $0)"
	exit 1
fi

# Check for Go version 1.13.*
GO_VERSION=$(go version | awk '{print $3}')
if [[ ! "${GO_VERSION}" =~ ^go1.13.* ]]; then
	echo "Go version must be >= go1.13"
	exit 1
fi

ARCHS=(darwin-amd64 linux-amd64 linux-arm64 linux-armv6 windows-amd64)

mkdir release

# Create architecture specific release dirs
for ARCH in "${ARCHS[@]}"; do
	mkdir release/${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}
done

# Create architecture specific binaries
GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" \
	-o release/${BINARY}-${VERSION}.darwin-amd64.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy
GO111MODULE=on GOOS=linux GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" \
	-o release/${BINARY}-${VERSION}.linux-amd64.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy
GO111MODULE=on GOOS=linux GOARCH=arm64 go build -ldflags="-X main.VERSION=${VERSION}" \
	-o release/${BINARY}-${VERSION}.linux-arm64.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy
GO111MODULE=on GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-X main.VERSION=${VERSION}" \
	-o release/${BINARY}-${VERSION}.linux-armv6.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy
GO111MODULE=on GOOS=windows GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" \
	-o release/${BINARY}-${VERSION}.windows-amd64.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy

cd release

for ARCH in ${ARCHS[@]}; do
	# Create sha256sum for architecture specific binary
	shasum -a 256 ${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}/${BINARY} > ${BINARY}-${VERSION}.${ARCH}-sha256sum.txt

	# Create tar file for architecture specific binary
	tar -czvf ${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}.tar.gz ${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}
done
