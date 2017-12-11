#!/bin/bash
# build binary distributions for linux/amd64 and darwin/amd64
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "working dir $DIR"
mkdir -p $DIR/dist
dep ensure || exit 1

os=$(go env GOOS)
arch=$(go env GOARCH)
version=$(cat $DIR/version.go | grep "const VERSION" | awk '{print $NF}' | sed 's/"//g')
goversion=$(go version | awk '{print $3}')
sha256sum=()

echo "... running tests"
./test.sh

for os in windows linux darwin; do
    echo "... building v$version for $os/$arch"
    EXT=
    if [ $os = windows ]; then
        EXT=".exe"
    fi
    BUILD=$(mktemp -d ${TMPDIR:-/tmp}/oauth2_proxy.XXXXXX)
    TARGET="oauth2_proxy-$version.$os-$arch.$goversion"
    FILENAME="oauth2_proxy-$version.$os-$arch$EXT"
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 \
        go build -ldflags="-s -w" -o $BUILD/$TARGET/$FILENAME || exit 1
    pushd $BUILD/$TARGET
    sha256sum+=("$(shasum -a 256 $FILENAME || exit 1)")
    cd .. && tar czvf $TARGET.tar.gz $TARGET
    mv $TARGET.tar.gz $DIR/dist
    popd
done

checksum_file="sha256sum.txt"
cd $DIR/dist
if [ -f $checksum_file ]; then
    rm $checksum_file
fi
touch $checksum_file
for checksum in "${sha256sum[@]}"; do
    echo "$checksum" >> $checksum_file
done
