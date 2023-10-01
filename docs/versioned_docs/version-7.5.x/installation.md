---
id: installation
title: Installation
slug: /
---

1.  Choose how to deploy:

    a. Download [Prebuilt Binary](https://github.com/oauth2-proxy/oauth2-proxy/releases) (current release is `v7.5.0`)

    b. Build with `$ go install github.com/oauth2-proxy/oauth2-proxy/v7@latest` which will put the binary in `$GOPATH/bin`

    c. Using the prebuilt docker image [quay.io/oauth2-proxy/oauth2-proxy](https://quay.io/oauth2-proxy/oauth2-proxy) (AMD64, PPC64LE, ARMv6, ARMv7, and ARM64 tags available)

    d. Using a [Kubernetes manifest](https://github.com/oauth2-proxy/manifests) (Helm)

Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.

```
$ sha256sum -c sha256sum.txt
oauth2-proxy-x.y.z.linux-amd64: OK
```

2.  [Select a Provider and Register an OAuth Application with a Provider](configuration/auth.md)
3.  [Configure OAuth2 Proxy using config file, command line options, or environment variables](configuration/overview.md)
4.  [Configure SSL or Deploy behind a SSL endpoint](configuration/tls.md) (example provided for Nginx)
