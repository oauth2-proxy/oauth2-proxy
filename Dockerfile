FROM golang:1.11-stretch AS builder
WORKDIR /go/src/github.com/pusher/oauth2_proxy
COPY . .

# Fetch dependencies
RUN wget -O dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64
RUN chmod +x dep
RUN mv dep $GOPATH/bin/dep
RUN dep ensure --vendor-only

# Build image
RUN ./configure && make clean oauth2_proxy

# Copy binary to debian
FROM debian:stretch
COPY --from=builder /go/src/github.com/pusher/oauth2_proxy/oauth2_proxy /bin/oauth2_proxy

ENTRYPOINT ["/bin/oauth2_proxy"]
