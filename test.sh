#!/bin/bash
go test -v -race $(go list ./... | grep -v /vendor/)
