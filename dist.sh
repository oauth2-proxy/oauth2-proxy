#!/usr/bin/env bash

set -o errexit

if [[ -z ${BINARY} ]] || [[ -z ${VERSION} ]]; then
	echo "Missing required env var: BINARY=X VERSION=X $(basename $0)"
	exit 1
fi

# Check for Go version 1.14.*
GO_VERSION=$(go version | awk '{print $3}')
if [[ ! "${GO_VERSION}" =~ ^go1.14.* ]]; then
	echo "Go version must be >= go1.14"
	exit 1
fi

ARCHS=(darwin-amd64 linux-amd64 linux-arm64 linux-armv6 freebsd-amd64 windows-amd64)

mkdir -p release

# Create architecture specific release dirs
for ARCH in "${ARCHS[@]}"; do
	mkdir -p release/${BINARY}-${VERSION}.${ARCH}

	GO_OS=$(echo $ARCH | awk -F- '{print $1}')
	GO_ARCH=$(echo $ARCH | awk -F- '{print $2}')

	# Create architecture specific binaries
	if [[ ${GO_ARCH} == "armv6" ]]; then
		GO111MODULE=on GOOS=${GO_OS} GOARCH=arm GOARM=6 CGO_ENABLED=0 go build -ldflags="-X main.VERSION=${VERSION}" \
			-o release/${BINARY}-${VERSION}.${ARCH}/${BINARY} github.com/oauth2-proxy/oauth2-proxy
	else
		GO111MODULE=on GOOS=${GO_OS} GOARCH=${GO_ARCH} CGO_ENABLED=0 go build -ldflags="-X main.VERSION=${VERSION}" \
			-o release/${BINARY}-${VERSION}.${ARCH}/${BINARY} github.com/oauth2-proxy/oauth2-proxy
	fi

	cd release

	# Create sha256sum for architecture specific binary
	sha256sum ${BINARY}-${VERSION}.${ARCH}/${BINARY} > ${BINARY}-${VERSION}.${ARCH}-sha256sum.txt

	# Create tar file for architecture specific binary
	tar -czvf ${BINARY}-${VERSION}.${ARCH}.tar.gz ${BINARY}-${VERSION}.${ARCH}

	cd ..
done
