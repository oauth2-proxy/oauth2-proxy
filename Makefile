include .env
BINARY := oauth2_proxy
VERSION := $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
.NOTPARALLEL:

.PHONY: all
all: dep lint $(BINARY)

.PHONY: clean
clean:
	rm -rf release
	rm -f $(BINARY)

.PHONY: distclean
distclean: clean
	rm -rf vendor

BIN_DIR := $(GOPATH)/bin
GOMETALINTER := $(BIN_DIR)/gometalinter

$(GOMETALINTER):
	$(GO) get -u github.com/alecthomas/gometalinter
	gometalinter --install %> /dev/null

.PHONY: lint
lint: $(GOMETALINTER)
	$(GOMETALINTER) --vendor --disable-all \
		--enable=vet \
		--enable=vetshadow \
		--enable=golint \
		--enable=ineffassign \
		--enable=goconst \
		--enable=deadcode \
		--enable=gofmt \
		--enable=goimports \
		--tests ./...

.PHONY: dep
dep:
	$(DEP) ensure --vendor-only

.PHONY: build
build: clean $(BINARY)

$(BINARY):
	CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X main.VERSION=${VERSION}" -o $@ github.com/pusher/oauth2_proxy

.PHONY: docker
docker:
	docker build -f Dockerfile -t quay.io/pusher/oauth2_proxy:latest .

.PHONY: docker-all
docker-all: docker
	docker build -f Dockerfile -t quay.io/pusher/oauth2_proxy:latest-amd64 .
	docker build -f Dockerfile -t quay.io/pusher/oauth2_proxy:${VERSION} .
	docker build -f Dockerfile -t quay.io/pusher/oauth2_proxy:${VERSION}-amd64 .
	docker build -f Dockerfile.arm64 -t quay.io/pusher/oauth2_proxy:latest-arm64 .
	docker build -f Dockerfile.arm64 -t quay.io/pusher/oauth2_proxy:${VERSION}-arm64 .
	docker build -f Dockerfile.armv6 -t quay.io/pusher/oauth2_proxy:latest-armv6 .
	docker build -f Dockerfile.armv6 -t quay.io/pusher/oauth2_proxy:${VERSION}-armv6 .

.PHONY: docker-push
docker-push:
	docker push quay.io/pusher/oauth2_proxy:latest

.PHONY: docker-push-all
docker-push-all: docker-push
	docker push quay.io/pusher/oauth2_proxy:latest-amd64
	docker push quay.io/pusher/oauth2_proxy:${VERSION}
	docker push quay.io/pusher/oauth2_proxy:${VERSION}-amd64
	docker push quay.io/pusher/oauth2_proxy:latest-arm64
	docker push quay.io/pusher/oauth2_proxy:${VERSION}-arm64
	docker push quay.io/pusher/oauth2_proxy:latest-armv6
	docker push quay.io/pusher/oauth2_proxy:${VERSION}-armv6

.PHONY: test
test: dep lint
	$(GO) test -v -race ./...

.PHONY: release
release: lint test
	mkdir release
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-darwin-amd64 github.com/pusher/oauth2_proxy
	GOOS=linux GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-linux-amd64 github.com/pusher/oauth2_proxy
	GOOS=linux GOARCH=arm64 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-linux-arm64 github.com/pusher/oauth2_proxy
	GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-linux-armv6 github.com/pusher/oauth2_proxy
	GOOS=windows GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-windows-amd64 github.com/pusher/oauth2_proxy
	shasum -a 256 release/$(BINARY)-darwin-amd64 > release/$(BINARY)-darwin-amd64-sha256sum.txt
	shasum -a 256 release/$(BINARY)-linux-amd64 > release/$(BINARY)-linux-amd64-sha256sum.txt
	shasum -a 256 release/$(BINARY)-linux-arm64 > release/$(BINARY)-linux-arm64-sha256sum.txt
	shasum -a 256 release/$(BINARY)-linux-armv6 > release/$(BINARY)-linux-armv6-sha256sum.txt
	shasum -a 256 release/$(BINARY)-windows-amd64 > release/$(BINARY)-windows-amd64-sha256sum.txt
	tar -czvf release/$(BINARY)-$(VERSION).darwin-amd64.$(GO_VERSION).tar.gz release/$(BINARY)-darwin-amd64
	tar -czvf release/$(BINARY)-$(VERSION).linux-amd64.$(GO_VERSION).tar.gz release/$(BINARY)-linux-amd64
	tar -czvf release/$(BINARY)-$(VERSION).linux-arm64.$(GO_VERSION).tar.gz release/$(BINARY)-linux-arm64
	tar -czvf release/$(BINARY)-$(VERSION).linux-armv6.$(GO_VERSION).tar.gz release/$(BINARY)-linux-armv6
	tar -czvf release/$(BINARY)-$(VERSION).windows-amd64.$(GO_VERSION).tar.gz release/$(BINARY)-windows-amd64
