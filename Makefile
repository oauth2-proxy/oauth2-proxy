GO ?= go
GOLANGCILINT ?= golangci-lint

BINARY := oauth2-proxy
VERSION ?= $(shell git describe --always --dirty --tags 2>/dev/null || echo "undefined")
# Allow to override image registry.
REGISTRY   ?= quay.io/oauth2-proxy
REPOSITORY ?= oauth2-proxy

DATE := $(shell date +"%Y%m%d")
.NOTPARALLEL:

GO_MAJOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 20
GO_VERSION_VALIDATION_ERR_MSG = Golang version is not supported, please update to at least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)

ifeq ($(COVER),true)
TESTCOVER ?= -coverprofile c.out
endif

.PHONY: all
all: lint $(BINARY)

.PHONY: clean
clean:
	-rm -rf release
	-rm -f $(BINARY)

.PHONY: distclean
distclean: clean
	rm -rf vendor

.PHONY: lint
lint: validate-go-version
	GO111MODULE=on $(GOLANGCILINT) run

.PHONY: build
build: validate-go-version clean $(BINARY)

$(BINARY):
	CGO_ENABLED=0 $(GO) build -a -installsuffix cgo -ldflags="-X github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version.VERSION=${VERSION}" -o $@ github.com/oauth2-proxy/oauth2-proxy/v7

DOCKER_BUILD_PLATFORM         ?= linux/amd64,linux/arm64,linux/ppc64le,linux/arm/v7,linux/s390x
DOCKER_BUILD_RUNTIME_IMAGE    ?= gcr.io/distroless/static:nonroot
DOCKER_BUILDX_ARGS            ?= --build-arg RUNTIME_IMAGE=${DOCKER_BUILD_RUNTIME_IMAGE} --build-arg VERSION=${VERSION}
DOCKER_BUILDX                 := docker buildx build ${DOCKER_BUILDX_ARGS} --pull
DOCKER_BUILDX_X_PLATFORM      := $(DOCKER_BUILDX) --platform ${DOCKER_BUILD_PLATFORM}
DOCKER_BUILDX_PUSH            := $(DOCKER_BUILDX) --push
DOCKER_BUILDX_PUSH_X_PLATFORM := $(DOCKER_BUILDX_PUSH) --platform ${DOCKER_BUILD_PLATFORM}

DOCKER_BUILD_PLATFORM_ALPINE         ?= linux/amd64,linux/arm64,linux/ppc64le,linux/arm/v6,linux/arm/v7,linux/s390x
DOCKER_BUILD_RUNTIME_IMAGE_ALPINE    ?= alpine:3.21.0
DOCKER_BUILDX_ARGS_ALPINE            ?= --build-arg RUNTIME_IMAGE=${DOCKER_BUILD_RUNTIME_IMAGE_ALPINE} --build-arg VERSION=${VERSION}
DOCKER_BUILDX_X_PLATFORM_ALPINE      := docker buildx build ${DOCKER_BUILDX_ARGS_ALPINE} --platform ${DOCKER_BUILD_PLATFORM_ALPINE}
DOCKER_BUILDX_PUSH_X_PLATFORM_ALPINE := $(DOCKER_BUILDX_X_PLATFORM_ALPINE) --push

.PHONY: docker
docker:
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):latest -t $(REGISTRY)/$(REPOSITORY):${VERSION} .
	$(DOCKER_BUILDX_X_PLATFORM_ALPINE) -t $(REGISTRY)/$(REPOSITORY):latest-alpine -t $(REGISTRY)/$(REPOSITORY):${VERSION}-alpine .

.PHONY: docker-push
docker-push:
	$(DOCKER_BUILDX_PUSH_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY):latest -t $(REGISTRY)/$(REPOSITORY):${VERSION} .
	$(DOCKER_BUILDX_PUSH_X_PLATFORM_ALPINE) -t $(REGISTRY)/$(REPOSITORY):latest-alpine -t $(REGISTRY)/$(REPOSITORY):${VERSION}-alpine .

.PHONY: docker-all
docker-all: docker
	$(DOCKER_BUILDX) --platform linux/amd64   -t $(REGISTRY)/$(REPOSITORY):latest-amd64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-amd64 .
	$(DOCKER_BUILDX) --platform linux/arm64   -t $(REGISTRY)/$(REPOSITORY):latest-arm64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-arm64 .
	$(DOCKER_BUILDX) --platform linux/ppc64le -t $(REGISTRY)/$(REPOSITORY):latest-ppc64le -t $(REGISTRY)/$(REPOSITORY):${VERSION}-ppc64le .
	$(DOCKER_BUILDX) --platform linux/arm/v7  -t $(REGISTRY)/$(REPOSITORY):latest-armv7   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-armv7 .
	$(DOCKER_BUILDX) --platform linux/s390x   -t $(REGISTRY)/$(REPOSITORY):latest-s390x -t $(REGISTRY)/$(REPOSITORY):${VERSION}-s390x .

.PHONY: docker-push-all
docker-push-all: docker-push
	$(DOCKER_BUILDX_PUSH) --platform linux/amd64   -t $(REGISTRY)/$(REPOSITORY):latest-amd64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-amd64 .
	$(DOCKER_BUILDX_PUSH) --platform linux/arm64   -t $(REGISTRY)/$(REPOSITORY):latest-arm64   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-arm64 .
	$(DOCKER_BUILDX_PUSH) --platform linux/ppc64le -t $(REGISTRY)/$(REPOSITORY):latest-ppc64le -t $(REGISTRY)/$(REPOSITORY):${VERSION}-ppc64le .
	$(DOCKER_BUILDX_PUSH) --platform linux/arm/v7  -t $(REGISTRY)/$(REPOSITORY):latest-armv7   -t $(REGISTRY)/$(REPOSITORY):${VERSION}-armv7 .
	$(DOCKER_BUILDX_PUSH) --platform linux/s390x   -t $(REGISTRY)/$(REPOSITORY):latest-s390x -t $(REGISTRY)/$(REPOSITORY):${VERSION}-s390x .

.PHONY: docker-nightly-build
docker-nightly-build:
	$(DOCKER_BUILDX_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY)-nightly:latest -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE} .
	$(DOCKER_BUILDX_X_PLATFORM_ALPINE) -t ${REGISTRY}/$(REPOSITORY)-nightly:latest-alpine -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE}-alpine .

.PHONY: docker-nightly-push
docker-nightly-push:
	$(DOCKER_BUILDX_PUSH_X_PLATFORM) -t $(REGISTRY)/$(REPOSITORY)-nightly:latest -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE} .
	$(DOCKER_BUILDX_PUSH_X_PLATFORM_ALPINE) -t ${REGISTRY}/$(REPOSITORY)-nightly:latest-alpine -t $(REGISTRY)/$(REPOSITORY)-nightly:${DATE}-alpine .

.PHONY: generate
generate:
	go generate ./pkg/...

.PHONY: verify-generate
verify-generate: generate
	git diff --exit-code

.PHONY: test
test: lint
	GO111MODULE=on $(GO) test $(TESTCOVER) -v -race ./...

.PHONY: release
release: validate-go-version lint test
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
#    make local-env-up          # Bring up a basic test environment
#    make local-env-down        # Tear down the basic test environment
#    make local-env-nginx-up    # Bring up an nginx based test environment
#    make local-env-nginx-down  # Tead down the nginx based test environment
.PHONY: local-env-%
local-env-%:
	make -C contrib/local-environment $*
