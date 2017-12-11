#!/bin/bash
EXIT_CODE=0
echo "gofmt"
diff -u <(echo -n) <(gofmt -d $(find . -type f -name '*.go' -not -path "./vendor/*")) || EXIT_CODE=1
for pkg in $(go list ./... | grep -v '/vendor/' ); do
    echo "testing $pkg"
    echo "go vet $pkg"
    go vet "$pkg" || EXIT_CODE=1
    echo "go test -v $pkg"
    go test -v -timeout 90s "$pkg" || EXIT_CODE=1
    echo "go test -v -race $pkg"
    GOMAXPROCS=4 go test -v -timeout 90s0s -race "$pkg" || EXIT_CODE=1
done
exit $EXIT_CODE