include .env
BINARY := oauth2_proxy
VERSION := $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
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
test: lint
	GO111MODULE=on $(GO) test -v -race ./...

.PHONY: release
release: lint test
	mkdir release
	mkdir release/$(BINARY)-$(VERSION).darwin-amd64.$(GO_VERSION)
	mkdir release/$(BINARY)-$(VERSION).linux-amd64.$(GO_VERSION)
	mkdir release/$(BINARY)-$(VERSION).linux-arm64.$(GO_VERSION)
	mkdir release/$(BINARY)-$(VERSION).linux-armv6.$(GO_VERSION)
	mkdir release/$(BINARY)-$(VERSION).windows-amd64.$(GO_VERSION)
	GO111MODULE=on GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" \
		-o release/$(BINARY)-$(VERSION).darwin-amd64.$(GO_VERSION)/$(BINARY) github.com/pusher/oauth2_proxy
	GO111MODULE=on GOOS=linux GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" \
		-o release/$(BINARY)-$(VERSION).linux-amd64.$(GO_VERSION)/$(BINARY) github.com/pusher/oauth2_proxy
	GO111MODULE=on GOOS=linux GOARCH=arm64 go build -ldflags="-X main.VERSION=${VERSION}" \
		-o release/$(BINARY)-$(VERSION).linux-arm64.$(GO_VERSION)/$(BINARY) github.com/pusher/oauth2_proxy
	GO111MODULE=on GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-X main.VERSION=${VERSION}" \
		-o release/$(BINARY)-$(VERSION).linux-armv6.$(GO_VERSION)/$(BINARY) github.com/pusher/oauth2_proxy
	GO111MODULE=on GOOS=windows GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" \
		-o release/$(BINARY)-$(VERSION).windows-amd64.$(GO_VERSION)/$(BINARY) github.com/pusher/oauth2_proxy
	shasum -a 256 release/$(BINARY)-$(VERSION).darwin-amd64.$(GO_VERSION)/$(BINARY) > release/$(BINARY)-$(VERSION).darwin-amd64-sha256sum.txt
	shasum -a 256 release/$(BINARY)-$(VERSION).linux-amd64.$(GO_VERSION)/$(BINARY) > release/$(BINARY)-$(VERSION).linux-amd64-sha256sum.txt
	shasum -a 256 release/$(BINARY)-$(VERSION).linux-arm64.$(GO_VERSION)/$(BINARY) > release/$(BINARY)-$(VERSION).linux-arm64-sha256sum.txt
	shasum -a 256 release/$(BINARY)-$(VERSION).linux-armv6.$(GO_VERSION)/$(BINARY) > release/$(BINARY)-$(VERSION).linux-armv6-sha256sum.txt
	shasum -a 256 release/$(BINARY)-$(VERSION).windows-amd64.$(GO_VERSION)/$(BINARY) > release/$(BINARY)-$(VERSION).windows-amd64-sha256sum.txt
	tar -C release -czvf release/$(BINARY)-$(VERSION).darwin-amd64.$(GO_VERSION).tar.gz $(BINARY)-$(VERSION).darwin-amd64.$(GO_VERSION)
	tar -C release -czvf release/$(BINARY)-$(VERSION).linux-amd64.$(GO_VERSION).tar.gz $(BINARY)-$(VERSION).linux-amd64.$(GO_VERSION)
	tar -C release -czvf release/$(BINARY)-$(VERSION).linux-arm64.$(GO_VERSION).tar.gz $(BINARY)-$(VERSION).linux-arm64.$(GO_VERSION)
	tar -C release -czvf release/$(BINARY)-$(VERSION).linux-armv6.$(GO_VERSION).tar.gz $(BINARY)-$(VERSION).linux-armv6.$(GO_VERSION)
	tar -C release -czvf release/$(BINARY)-$(VERSION).windows-amd64.$(GO_VERSION).tar.gz $(BINARY)-$(VERSION).windows-amd64.$(GO_VERSION)
