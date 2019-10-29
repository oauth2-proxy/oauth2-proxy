include .env
BINARY := oauth2_proxy
VERSION := $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
# Allow to override image registry.
REGISTRY ?= quay.io/pusher
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
	GO111MODULE=on CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X main.VERSION=${VERSION}" -o $@ github.com/pusher/oauth2_proxy

.PHONY: docker
docker:
	docker build -f Dockerfile -t $(REGISTRY)/oauth2_proxy:latest .

.PHONY: docker-all
docker-all: docker
	docker build -f Dockerfile -t $(REGISTRY)/oauth2_proxy:latest-amd64 .
	docker build -f Dockerfile -t $(REGISTRY)/oauth2_proxy:${VERSION} .
	docker build -f Dockerfile -t $(REGISTRY)/oauth2_proxy:${VERSION}-amd64 .
	docker build -f Dockerfile.arm64 -t $(REGISTRY)/oauth2_proxy:latest-arm64 .
	docker build -f Dockerfile.arm64 -t $(REGISTRY)/oauth2_proxy:${VERSION}-arm64 .
	docker build -f Dockerfile.armv6 -t $(REGISTRY)/oauth2_proxy:latest-armv6 .
	docker build -f Dockerfile.armv6 -t $(REGISTRY)/oauth2_proxy:${VERSION}-armv6 .

.PHONY: docker-push
docker-push:
	docker push $(REGISTRY)/oauth2_proxy:latest

.PHONY: docker-push-all
docker-push-all: docker-push
	docker push $(REGISTRY)/oauth2_proxy:latest-amd64
	docker push $(REGISTRY)/oauth2_proxy:${VERSION}
	docker push $(REGISTRY)/oauth2_proxy:${VERSION}-amd64
	docker push $(REGISTRY)/oauth2_proxy:latest-arm64
	docker push $(REGISTRY)/oauth2_proxy:${VERSION}-arm64
	docker push $(REGISTRY)/oauth2_proxy:latest-armv6
	docker push $(REGISTRY)/oauth2_proxy:${VERSION}-armv6

.PHONY: test
test: lint
	GO111MODULE=on $(GO) test -v -race ./...

.PHONY: release
release: lint test
	BINARY=${BINARY} VERSION=${VERSION} ./dist.sh
