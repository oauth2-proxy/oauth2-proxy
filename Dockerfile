FROM golang:1.10 AS builder
WORKDIR /go/src/github.com/pusher/oauth2_proxy
COPY . .

# Fetch dependencies
RUN go get -u github.com/golang/dep/cmd/dep
RUN dep ensure --vendor-only

# Build image
RUN CGO_ENABLED=0 GOOS=linux go build

# Copy binary to alpine
FROM alpine:3.8
COPY --from=builder /go/src/github.com/pusher/oauth2_proxy/oauth2_proxy /bin/oauth2_proxy

ENTRYPOINT ["/bin/oauth2_proxy"]
