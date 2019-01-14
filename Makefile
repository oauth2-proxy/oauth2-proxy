include .env
BINARY := oauth2_proxy
VERSION := $(shell git describe --always --long --dirty --tags 2>/dev/null || echo "undefined")
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
	$(GO) build -ldflags="-X main.VERSION=${VERSION}" -o $(BINARY) github.com/pusher/oauth2_proxy

.PHONY: test
test: dep lint
	$(GO) test -v -race $(go list ./... | grep -v /vendor/)

.PHONY: release
release: lint test
	mkdir release
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-darwin-amd64 github.com/pusher/oauth2_proxy
	GOOS=linux GOARCH=amd64 go build -ldflags="-X main.VERSION=${VERSION}" -o release/$(BINARY)-linux-amd64 github.com/pusher/oauth2_proxy
