#!/bin/bash
gometalinter --vendor --disable-all \
--enable=vet \
--enable=vetshadow \
--enable=golint \
--enable=ineffassign \
--enable=goconst \
--enable=deadcode \
--enable=gofmt \
--enable=goimports \
--tests ./...
