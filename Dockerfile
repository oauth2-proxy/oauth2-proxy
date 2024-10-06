# This ARG has to be at the top, otherwise the docker daemon does not known what to do with FROM ${RUNTIME_IMAGE}
ARG RUNTIME_IMAGE=gcr.io/distroless/static:nonroot
# version is shared between mutiple buildstages
ARG VERSION

# All builds should be done using the platform native to the build node to allow
#  cache sharing of the go mod download step.
# Go cross compilation is also faster than emulation the go compilation across
#  multiple platforms.
FROM --platform=${BUILDPLATFORM} docker.io/library/golang:1.22-bookworm AS builder

# Copy sources
WORKDIR $GOPATH/src/github.com/oauth2-proxy/oauth2-proxy

# Fetch dependencies
COPY go.mod go.sum ./
RUN go mod download

# Now pull in our code
COPY . .

# Arguments go here so that the previous steps can be cached if no external
#  sources have changed.
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Build binary and make sure there is at least an empty key file.
#  This is useful for GCP App Engine custom runtime builds, because
#  you cannot use multiline variables in their app.yaml, so you have to
#  build the key into the container and then tell it where it is
#  by setting OAUTH2_PROXY_JWT_KEY_FILE=/etc/ssl/private/jwt_signing_key.pem
#  in app.yaml instead.
# Set the cross compilation arguments based on the TARGETPLATFORM which is
#  automatically set by the docker engine.
RUN case ${TARGETPLATFORM} in \
         "linux/amd64")  GOARCH=amd64  ;; \
         # arm64 and arm64v8 are equivalent in go and do not require a goarm
         # https://github.com/golang/go/wiki/GoArm
         "linux/arm64" | "linux/arm/v8")  GOARCH=arm64  ;; \
         "linux/ppc64le")  GOARCH=ppc64le  ;; \
         "linux/s390x")  GOARCH=s390x  ;; \
         "linux/arm/v6") GOARCH=arm GOARM=6  ;; \
         "linux/arm/v7") GOARCH=arm GOARM=7 ;; \
    esac && \
    printf "Building OAuth2 Proxy for arch ${GOARCH}\n" && \
    GOARCH=${GOARCH} VERSION=${VERSION} make build && touch jwt_signing_key.pem

# Copy binary to runtime image
FROM ${RUNTIME_IMAGE}
ARG VERSION

COPY --from=builder /go/src/github.com/oauth2-proxy/oauth2-proxy/oauth2-proxy /bin/oauth2-proxy
COPY --from=builder /go/src/github.com/oauth2-proxy/oauth2-proxy/jwt_signing_key.pem /etc/ssl/private/jwt_signing_key.pem

LABEL org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.description="A reverse proxy that provides authentication with Google, Azure, OpenID Connect and many more identity providers." \
      org.opencontainers.image.documentation=https://oauth2-proxy.github.io/oauth2-proxy/ \
      org.opencontainers.image.source=https://github.com/oauth2-proxy/oauth2-proxy \
      org.opencontainers.image.url=https://quay.io/oauth2-proxy/oauth2-proxy \
      org.opencontainers.image.title=oauth2-proxy \
      org.opencontainers.image.version=${VERSION}

ENTRYPOINT ["/bin/oauth2-proxy"]
