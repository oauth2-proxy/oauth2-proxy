FROM golang:1.13-buster AS builder

# Download tools
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin v1.17.1

# Copy sources
WORKDIR $GOPATH/src/github.com/pusher/oauth2_proxy

# Fetch dependencies
COPY go.mod go.sum ./
RUN GO111MODULE=on go mod download

# Now pull in our code
COPY . .

# Build binary and make sure there is at least an empty key file.
#  This is useful for GCP App Engine custom runtime builds, because
#  you cannot use multiline variables in their app.yaml, so you have to
#  build the key into the container and then tell it where it is
#  by setting OAUTH2_PROXY_JWT_KEY_FILE=/etc/ssl/private/jwt_signing_key.pem
#  in app.yaml instead.
RUN ./configure && make build && touch jwt_signing_key.pem

# Copy binary to alpine
FROM alpine:3.10
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/pusher/oauth2_proxy/oauth2_proxy /bin/oauth2_proxy
COPY --from=builder /go/src/github.com/pusher/oauth2_proxy/jwt_signing_key.pem /etc/ssl/private/jwt_signing_key.pem

USER 2000:2000

ENTRYPOINT ["/bin/oauth2_proxy"]
