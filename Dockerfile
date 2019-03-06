FROM golang:1.12.0-stretch AS builder

# Download tools
RUN wget -O $GOPATH/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64
RUN chmod +x $GOPATH/bin/dep

# Copy sources
WORKDIR $GOPATH/src/github.com/pusher/oauth2_proxy
COPY ./Gopkg.* ./

# Fetch dependencies
RUN dep ensure --vendor-only

COPY . .
# Build binary
RUN ./configure && make build

FROM gcr.io/distroless/static:latest
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/pusher/oauth2_proxy/oauth2_proxy /bin/oauth2_proxy

USER 2000:2000
ENTRYPOINT ["/bin/oauth2_proxy"]
