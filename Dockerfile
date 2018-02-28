FROM golang:1.9 AS builder
WORKDIR /go/src/github.com/bitly/oauth2_proxy
COPY . .
RUN go get -d -v; \
    CGO_ENABLED=0 GOOS=linux go build

FROM scratch
COPY --from=builder /go/src/github.com/bitly/oauth2_proxy/oauth2_proxy /bin/oauth2_proxy

ENTRYPOINT ["/bin/oauth2_proxy"]
