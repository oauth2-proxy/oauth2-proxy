#!/usr/bin/env bash

#
# Makefile with some common workflow for dev, build and test
#

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

# The following help command is Licensed under the Apache License, Version 2.0 (the "License")
# Copyright 2023 The Kubernetes Authors.
.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


GO ?= go
GOLANGCILINT ?= golangci-lint

BINARY := oauth2-proxy
VERSION ?= $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
# Allow to override image registry.
REGISTRY   ?= quay.io/oauth2-proxy
REPOSITORY ?= oauth2-proxy

DATE := $(shell date +"%Y%m%d")
.NOTPARALLEL:

# The go version in go.mod used for the Docker build toolchain, without the patch
GO_MOD_VERSION_MINOR := $(shell $(GO) list -f '{{printf "%.4s" .Module.GoVersion}}' )

# From go1.21 go will transparently download the toolchain declared in go.mod. https://go.dev/doc/toolchain
# We don't need to keep this message updated: the important info is in go.mod.
GO_VERSION_VALIDATION_ERR_MSG = Golang version is not supported, please update to at least go1.21

ifeq ($(COVER),true)
TESTCOVER ?= -coverprofile c.out
endif

##@ Build

.PHONY: build
build: validate-go-version clean $(BINARY) ## Build and create oauth2-proxy binary from current source code

$(BINARY):
	CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version.VERSION=${VERSION}" -o $@ github.com/oauth2-proxy/oauth2-proxy/v7

DOCKER_BUILDX_COMMON_ARGS     ?= --build-arg BUILD_IMAGE=docker.io/library/golang:$(GO_MOD_VERSION_MINOR)-bookworm --build-arg VERSION=$(VERSION)

DOCKER_BUILD_PLATFORM         ?= linux/amd64,linux/arm64,linux/ppc64le,linux/arm/v7,linux/s390x
DOCKER_BUILD_RUNTIME_IMAGE    ?= gcr.io/distroless/static:nonroot
DOCKER_BUILDX_ARGS            ?= --build-arg RUNTIME_IMAGE=${DOCKER_BUILD_RUNTIME_IMAGE} ${DOCKER_BUILDX_COMMON_ARGS}
DOCKER_BUILDX                 := docker buildx build ${DOCKER_BUILDX_ARGS} --pull
DOCKER_BUILDX_X_PLATFORM      := $(DOCKER_BUILDX) --platform ${DOCKER_BUILD_PLATFORM}
DOCKER_BUILDX_PUSH            := $(DOCKER_BUILDX) --push
DOCKER_BUILDX_PUSH_X_PLATFORM := $(DOCKER_BUILDX_PUSH) --platform ${DOCKER_BUILD_PLATFORM}

DOCKER_BUILD_PLATFORM_ALPINE         ?= linux/amd64,linux/arm64,linux/ppc64le,linux/arm/v6,linux/arm/v7,linux/s390x
DOCKER_BUILD_RUNTIME_IMAGE_ALPINE    ?= alpine:3.22.2
DOCKER_BUILDX_ARGS_ALPINE            ?= --build-arg RUNTIME_IMAGE=${DOCKER_BUILD_RUNTIME_IMAGE_ALPINE} ${DOCKER_BUILDX_COMMON_ARGS}
DOCKER_BUILDX_X_PLATFORM_ALPINE      := docker buildx build ${DOCKER_BUILDX_ARGS_ALPINE} --platform ${DOCKER_BUILD_PLATFORM_ALPINE}
DOCKER_BUILDX_PUSH_X_PLATFORM_ALPINE := $(DOCKER_BUILDX_X_PLATFORM_ALPINE) --push

.PHONY: build-docker
build-docker: build-distroless build-alpine ## Build multi architecture docker images in both flavours (distroless / alpine)

.PHONY: build-docker-local
build-docker-local: ## Build distroless docker image and locally load into docker images
	$(DOCKER_BUILDX) --load -t $(REGISTRY)/$(REPOSITORY):${VERSION}-local .

.PHONY: build-distroless
build-distroless: ## Build multi architecture distroless based docker image
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):latest -t $(REGISTRY)/$(REPOSITORY):${VERSION} .

.PHONY: build-alpine
build-alpine: ## Build multi architecture alpine based docker image
	$(DOCKER_BUILDX_X_PLATFORM_ALPINE) -t $(REGISTRY)/$(REPOSITORY):latest-alpine -t $(REGISTRY)/$(REPOSITORY):${VERSION}-alpine .

.PHONY: build-docker-all
build-docker-all: build-docker ## Build docker images for all supported architectures in both flavours (distroless / alpine)
	$(DOCKER_BUILDX) --platform linux/amd64   -t $(REGISTRY)/$(REPOSITORY):latest-amd64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-amd64 .
	$(DOCKER_BUILDX) --platform linux/arm64   -t $(REGISTRY)/$(REPOSITORY):latest-arm64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-arm64 .
	$(DOCKER_BUILDX) --platform linux/ppc64le -t $(REGISTRY)/$(REPOSITORY):latest-ppc64le -t $(REGISTRY)/$(REPOSITORY):${VERSION}-ppc64le .
	$(DOCKER_BUILDX) --platform linux/arm/v7  -t $(REGISTRY)/$(REPOSITORY):latest-armv7   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-armv7 .
	$(DOCKER_BUILDX) --platform linux/s390x   -t $(REGISTRY)/$(REPOSITORY):latest-s390x -t $(REGISTRY)/$(REPOSITORY):${VERSION}-s390x .


##@ Publish

.PHONY: push-docker
push-docker: push-distroless push-alpine ## Push multi architecture docker images for both flavours (distroless / alpine)

.PHONY: push-distroless
push-distroless: ## Push multi architecture distroless based docker image
	$(DOCKER_BUILDX_PUSH_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):latest -t $(REGISTRY)/$(REPOSITORY):${VERSION} .

.PHONY: push-alpine
push-alpine: ## Push multi architecture alpine based docker image
	$(DOCKER_BUILDX_PUSH_X_PLATFORM_ALPINE) -t $(REGISTRY)/$(REPOSITORY):latest-alpine -t $(REGISTRY)/$(REPOSITORY):${VERSION}-alpine .

.PHONY: push-docker-all
push-docker-all: push-docker ## Push docker images for all supported architectures for both flavours (distroless / alpine)
	$(DOCKER_BUILDX_PUSH) --platform linux/amd64   -t $(REGISTRY)/$(REPOSITORY):latest-amd64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-amd64 .
	$(DOCKER_BUILDX_PUSH) --platform linux/arm64   -t $(REGISTRY)/$(REPOSITORY):latest-arm64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-arm64 .
	$(DOCKER_BUILDX_PUSH) --platform linux/ppc64le -t $(REGISTRY)/$(REPOSITORY):latest-ppc64le -t $(REGISTRY)/$(REPOSITORY):${VERSION}-ppc64le .
	$(DOCKER_BUILDX_PUSH) --platform linux/arm/v7  -t $(REGISTRY)/$(REPOSITORY):latest-armv7   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-armv7 .
	$(DOCKER_BUILDX_PUSH) --platform linux/s390x   -t $(REGISTRY)/$(REPOSITORY):latest-s390x -t $(REGISTRY)/$(REPOSITORY):${VERSION}-s390x .


##@ Nightly scheduling

.PHONY: nightly-build
nightly-build: ## Nightly build command for docker images in both flavours (distroless / alpine)
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY)-nightly:latest -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE} .
	$(DOCKER_BUILDX_X_PLATFORM_ALPINE) -t ${REGISTRY}/$(REPOSITORY)-nightly:latest-alpine -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE}-alpine .

.PHONY: nightly-push
nightly-push: ## Nightly push command for docker images in both flavours (distroless / alpine)
	$(DOCKER_BUILDX_PUSH_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY)-nightly:latest -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE} .
	$(DOCKER_BUILDX_PUSH_X_PLATFORM_ALPINE) -t ${REGISTRY}/$(REPOSITORY)-nightly:latest-alpine -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE}-alpine .


##@ Docs

.PHONY: generate
generate: ## Generate alpha config docs from golang structs
	go generate ./pkg/...

.PHONY: verify-generate
verify-generate: generate ## Verify command to check if alpha config docs are in line with golang struct changes
	git diff --exit-code

##@ Miscellaneous

.PHONY: test
test: lint ## Run all Go tests
	GO111MODULE=on $(GO) test $(TESTCOVER) -v -race ./...

.PHONY: release
release: validate-go-version lint test ## Create a full release for all architectures (binaries and checksums)
	BINARY=${BINARY} VERSION=${VERSION} ./dist.sh

.PHONY: clean
clean: ## Cleanup release and build files
	-rm -rf release
	-rm -f $(BINARY)

.PHONY: lint
lint: validate-go-version ## Lint all files using golangci-lint
	GO111MODULE=on $(GOLANGCILINT) run

.PHONY: validate-go-version
validate-go-version: ## Validate Go environment requirements
	@$(GO) list . >/dev/null || { echo '$(GO_VERSION_VALIDATION_ERR_MSG)'; exit 1; }

# local-env can be used to interact with the local development environment
# eg:
#    make local-env-up          # Bring up a basic test environment
#    make local-env-down        # Tear down the basic test environment
#    make local-env-nginx-up    # Bring up an nginx based test environment
#    make local-env-nginx-down  # Tead down the nginx based test environment
.PHONY: local-env-%
local-env-%:
	make -C contrib/local-environment $*
