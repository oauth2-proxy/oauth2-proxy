FROM golang:1.11-stretch AS builder

# Download tools
RUN wget -O $GOPATH/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64
RUN chmod +x $GOPATH/bin/dep

# Copy sources
WORKDIR $GOPATH/src/github.com/pusher/oauth2_proxy
COPY . .

# Fetch dependencies
RUN dep ensure --vendor-only

# Build binary
RUN ./configure && make build

# Copy binary to alpine
FROM alpine:3.8
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/src/github.com/pusher/oauth2_proxy/oauth2_proxy /bin/oauth2_proxy

ENTRYPOINT ["/bin/oauth2_proxy"]
