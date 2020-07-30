GO ?= go
GOLANGCILINT ?= golangci-lint

BINARY := oauth2-proxy
VERSION ?= $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
# Allow to override image registry.
REGISTRY ?= quay.io/oauth2-proxy
.NOTPARALLEL:

GO_MAJOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 14
GO_VERSION_VALIDATION_ERR_MSG = Golang version is not supported, please update to at least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)

DOCKER_BUILD := docker build --build-arg VERSION=${VERSION}

ifeq ($(COVER),true)
TESTCOVER ?= -coverprofile c.out
endif

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
lint: validate-go-version
	GO111MODULE=on $(GOLANGCILINT) run

.PHONY: build
build: validate-go-version clean $(BINARY)

$(BINARY):
	GO111MODULE=on CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X main.VERSION=${VERSION}" -o $@ github.com/oauth2-proxy/oauth2-proxy

.PHONY: docker
docker:
	$(DOCKER_BUILD) -f Dockerfile -t $(REGISTRY)/oauth2-proxy:latest .

.PHONY: docker-all
docker-all: docker
	$(DOCKER_BUILD) -f Dockerfile -t $(REGISTRY)/oauth2-proxy:latest-amd64 .
	$(DOCKER_BUILD) -f Dockerfile -t $(REGISTRY)/oauth2-proxy:${VERSION} .
	$(DOCKER_BUILD) -f Dockerfile -t $(REGISTRY)/oauth2-proxy:${VERSION}-amd64 .
	$(DOCKER_BUILD) -f Dockerfile.arm64 -t $(REGISTRY)/oauth2-proxy:latest-arm64 .
	$(DOCKER_BUILD) -f Dockerfile.arm64 -t $(REGISTRY)/oauth2-proxy:${VERSION}-arm64 .
	$(DOCKER_BUILD) -f Dockerfile.armv6 -t $(REGISTRY)/oauth2-proxy:latest-armv6 .
	$(DOCKER_BUILD) -f Dockerfile.armv6 -t $(REGISTRY)/oauth2-proxy:${VERSION}-armv6 .

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
	GO111MODULE=on $(GO) test $(TESTCOVER) -v -race ./...

.PHONY: release
release: lint test
	BINARY=${BINARY} VERSION=${VERSION} ./dist.sh

.PHONY: validate-go-version
validate-go-version:
	@if [ $(GO_MAJOR_VERSION) -gt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $(GO_MAJOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi

# local-env can be used to interact with the local development environment
# eg:
#    make local-env-up 					# Bring up a basic test environment
#    make local-env-down 				# Tear down the basic test environment
#    make local-env-nginx-up 		# Bring up an nginx based test environment
#    make local-env-nginx-down 	# Tead down the nginx based test environment
.PHONY: local-env-%
local-env-%:
	make -C contrib/local-environment $*

SHELL=/usr/bin/env bash -o pipefail
BIN_DIR ?= $(shell pwd)/tmp/bin

GOJSONTOYAML ?= $(BIN_DIR)/gojsontoyaml
JSONNET ?= $(BIN_DIR)/jsonnet
JSONNET_BUNDLER ?= $(BIN_DIR)/jb
JSONNET_FMT ?= $(BIN_DIR)/jsonnetfmt

JSONNET_DIR := contrib/jsonnet
MANIFESTS := contrib/manifests

JSONNET_SRC = $(shell find $(JSONNET_DIR) -name 'vendor' -prune -o -name 'jsonnet/vendor' -prune -o -name 'tmp' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print)
JSONNET_FMT_CMD := $(JSONNET_FMT) -n 2 --max-blank-lines 2 --string-style s --comment-style s

k8s: $(MANIFESTS) jsonnetfmt

.PHONY: $(MANIFESTS)
$(MANIFESTS): $(JSONNET) $(GOJSONTOYAML) $(JSONNET_DIR)/vendor $(JSONNET_DIR)/kustomize.jsonnet
	@rm -rf $(MANIFESTS)
	@mkdir -p $(MANIFESTS)
	$(JSONNET) -J $(JSONNET_DIR)/vendor -m $(MANIFESTS) $(JSONNET_DIR)/kustomize.jsonnet | xargs -I{} sh -c 'gojsontoyaml < {} > {}.yaml; rm -f {}' -- {}

.PHONY: jsonnetfmt
jsonnetfmt: $(JSONNET_FMT)
	PATH=$$PATH:$$(pwd)/$(BIN_DIR) echo $(JSONNET_SRC) | xargs -n 1 -- $(JSONNET_FMT_CMD) -i

contrib/jsonnet/vendor: | $(JSONNET_BUNDLER) $(JSONNET_DIR)/jsonnetfile.json $(JSONNET_DIR)/jsonnetfile.lock.json
	@cd $(JSONNET_DIR)
	$(JSONNET_BUNDLER) install

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(GOJSONTOYAML): $(BIN_DIR)
	$(GO) get -d github.com/brancz/gojsontoyaml
	$(GO) build -o $@ github.com/brancz/gojsontoyaml

$(JSONNET): $(BIN_DIR)
	$(GO) get -d github.com/google/go-jsonnet/cmd/jsonnet
	$(GO) build -o $@ github.com/google/go-jsonnet/cmd/jsonnet

$(JSONNET_FMT): $(BIN_DIR)
	$(GO) get -d github.com/google/go-jsonnet/cmd/jsonnetfmt
	$(GO) build -o $@ github.com/google/go-jsonnet/cmd/jsonnetfmt

$(JSONNET_BUNDLER): $(BIN_DIR)
	curl -sSfL -o $(JSONNET_BUNDLER) "https://github.com/jsonnet-bundler/jsonnet-bundler/releases/download/v0.4.0/jb-$(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH)"
	chmod +x $(JSONNET_BUNDLER)
