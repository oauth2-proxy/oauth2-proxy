---
id: installation
title: Installation
---

1.  Choose how to deploy:

    a. Using a [Prebuilt Binary](https://github.com/oauth2-proxy/oauth2-proxy/releases) (current release is `v7.7.1`)

    b. Using Go to install the latest release
    ```bash
    $ go install github.com/oauth2-proxy/oauth2-proxy/v7@latest
    ```
    This will install the binary into `$GOPATH/bin`. Make sure you include `$GOPATH` in your `$PATH`. Otherwise your system won't find binaries installed via `go install`

    c. Using a [Prebuilt Docker Image](https://quay.io/oauth2-proxy/oauth2-proxy) (AMD64, PPC64LE, S390x, ARMv6, ARMv7, and ARM64 available)

    d. Using a [Pre-Release Nightly Docker Image](https://quay.io/oauth2-proxy/oauth2-proxy-nightly) (AMD64, PPC64LE, ARMv6, ARMv7, and ARM64 available)

    e. Using the official [Kubernetes manifest](https://github.com/oauth2-proxy/manifests) (Helm)

    Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.
    
    ```
    $ sha256sum -c sha256sum.txt
    oauth2-proxy-x.y.z.linux-amd64: OK
    ```

2.  [Select a Provider and Register an OAuth Application with a Provider](configuration/providers/index.md)
3.  [Configure OAuth2 Proxy using config file, command line options, or environment variables](configuration/overview.md)
4.  [Configure SSL or Deploy behind an SSL endpoint](configuration/tls.md) (example provided for Nginx)
5.  [Configure OAuth2 Proxy using systemd.socket](configuration/systemd_socket.md) (example provided for Nginx/Systemd)
