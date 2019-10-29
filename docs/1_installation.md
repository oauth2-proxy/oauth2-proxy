---
layout: default
title: Installation
permalink: /installation
nav_order: 1
---

## Installation

1.  Choose how to deploy:

    a. Download [Prebuilt Binary](https://github.com/pusher/oauth2_proxy/releases) (current release is `v4.0.0`)

    b. Build with `$ go get github.com/pusher/oauth2_proxy` which will put the binary in `$GOROOT/bin`

    c. Using the prebuilt docker image [quay.io/pusher/oauth2_proxy](https://quay.io/pusher/oauth2_proxy) (AMD64, ARMv6 and ARM64 tags available)

Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.

```
$ sha256sum -c sha256sum.txt 2>&1 | grep OK
oauth2_proxy-4.0.0.linux-amd64: OK
```

2.  [Select a Provider and Register an OAuth Application with a Provider](auth-configuration)
3.  [Configure OAuth2 Proxy using config file, command line options, or environment variables](configuration)
4.  [Configure SSL or Deploy behind a SSL endpoint](tls-configuration) (example provided for Nginx)
