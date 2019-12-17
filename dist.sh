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

ARCHS=(darwin-amd64 linux-amd64 linux-arm64 linux-armv6 freebsd-amd64 windows-amd64)

mkdir -p release

# Create architecture specific release dirs
for ARCH in "${ARCHS[@]}"; do
	mkdir -p release/${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}

	GO_OS=$(echo $ARCH | awk -F- '{print $1}')
	GO_ARCH=$(echo $ARCH | awk -F- '{print $2}')

	# Create architecture specific binaries
	if [[ ${GO_ARCH} == "armv6" ]]; then
		GO111MODULE=on GOOS=${GO_OS} GOARCH=arm GOARM=6 go build -ldflags="-X main.VERSION=${VERSION}" \
			-o release/${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy
	else
		GO111MODULE=on GOOS=${GO_OS} GOARCH=${GO_ARCH} go build -ldflags="-X main.VERSION=${VERSION}" \
			-o release/${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}/${BINARY} github.com/pusher/oauth2_proxy
	fi

	cd release

	# Create sha256sum for architecture specific binary
	sha256sum ${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}/${BINARY} > ${BINARY}-${VERSION}.${ARCH}-sha256sum.txt

	# Create tar file for architecture specific binary
	tar -czvf ${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}.tar.gz ${BINARY}-${VERSION}.${ARCH}.${GO_VERSION}

	cd ..
done
