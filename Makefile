include .env
BINARY := oauth2-proxy
VERSION := $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
# Allow to override image registry.
REGISTRY ?= quay.io/oauth2-proxy
.NOTPARALLEL:

.PHONY: all
all: lint $(BINARY)

.PHONY: clean
clean:
	rm -rf release
	rm -f $(BINARY)

.PHONY: distclean
distclean: clean
	rm -rf vendor

.PHONY: lint
lint:
	GO111MODULE=on $(GOLANGCILINT) run

.PHONY: build
build: clean $(BINARY)

$(BINARY):
	GO111MODULE=on CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X main.VERSION=${VERSION}" -o $@ github.com/oauth2-proxy/oauth2-proxy

.PHONY: docker
docker:
	docker build -f Dockerfile -t $(REGISTRY)/oauth2-proxy:latest .

.PHONY: docker-all
docker-all: docker
	docker build -f Dockerfile -t $(REGISTRY)/oauth2-proxy:latest-amd64 .
	docker build -f Dockerfile -t $(REGISTRY)/oauth2-proxy:${VERSION} .
	docker build -f Dockerfile -t $(REGISTRY)/oauth2-proxy:${VERSION}-amd64 .
	docker build -f Dockerfile.arm64 -t $(REGISTRY)/oauth2-proxy:latest-arm64 .
	docker build -f Dockerfile.arm64 -t $(REGISTRY)/oauth2-proxy:${VERSION}-arm64 .
	docker build -f Dockerfile.armv6 -t $(REGISTRY)/oauth2-proxy:latest-armv6 .
	docker build -f Dockerfile.armv6 -t $(REGISTRY)/oauth2-proxy:${VERSION}-armv6 .

.PHONY: docker-push
docker-push:
	docker push $(REGISTRY)/oauth2-proxy:latest

.PHONY: docker-push-all
docker-push-all: docker-push
	docker push $(REGISTRY)/oauth2-proxy:latest-amd64
	docker push $(REGISTRY)/oauth2-proxy:${VERSION}
	docker push $(REGISTRY)/oauth2-proxy:${VERSION}-amd64
	docker push $(REGISTRY)/oauth2-proxy:latest-arm64
	docker push $(REGISTRY)/oauth2-proxy:${VERSION}-arm64
	docker push $(REGISTRY)/oauth2-proxy:latest-armv6
	docker push $(REGISTRY)/oauth2-proxy:${VERSION}-armv6

.PHONY: test
test: lint
	GO111MODULE=on $(GO) test -v -race ./...

.PHONY: release
release: lint test
	BINARY=${BINARY} VERSION=${VERSION} ./dist.sh
