# Building

This project is setup to build on amd64.

It is also possible to cross build binaries and docker images for armv6 and arm64.

## Clone repo and configure

```bash
cd $GOPATH/src/github.com # Create this directory if it doesn't exist
git clone git@github.com:<YOUR_FORK>/oauth2_proxy pusher/oauth2_proxy
cd pusher/oauth2_proxy
./configure # Setup your environment variables
make dep
```

## Building amd64

Build binary:
```bash
make
```

Build docker image:
```bash
make docker
```

## Building for other architectures

This requires [multiarch/qemu-user-static](https://github.com/multiarch/qemu-user-static) to be installed in your system.
On Ubuntu:
```bash
sudo apt install qemu-user-static
```

Register `qemu-user-static` on your system:
```bash
# make qemu-register
# or
sudo docker run --rm --privileged multiarch/qemu-user-static:register
```

Build all binaries:
```bash
make release
```

Build all docker images:
```bash
make docker-all
```
