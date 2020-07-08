---
layout: default
title: Installation
permalink: /installation
nav_order: 1
---

## Installation

1.  Choose how to deploy:

    a. Download [Prebuilt Binary](https://github.com/oauth2-proxy/oauth2-proxy/releases) (current release is `v6.0.0`)

    b. Build with `$ go get github.com/oauth2-proxy/oauth2-proxy` which will put the binary in `$GOROOT/bin`

    c. Using the prebuilt docker image [quay.io/oauth2-proxy/oauth2-proxy](https://quay.io/oauth2-proxy/oauth2-proxy) (AMD64, ARMv6 and ARM64 tags available)

Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.

```
$ sha256sum -c sha256sum.txt 2>&1 | grep OK
oauth2-proxy-x.y.z.linux-amd64: OK
```

2.  [Select a Provider and Register an OAuth Application with a Provider](auth-configuration)
3.  [Configure OAuth2 Proxy using config file, command line options, or environment variables](configuration)
4.  [Configure SSL or Deploy behind a SSL endpoint](tls-configuration) (example provided for Nginx)
