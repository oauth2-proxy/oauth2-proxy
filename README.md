![OAuth2 Proxy](/docs/static/img/logos/OAuth2_Proxy_horizontal.svg)

[![Continuous Integration](https://github.com/oauth2-proxy/oauth2-proxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/oauth2-proxy/oauth2-proxy/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/oauth2-proxy/oauth2-proxy)](https://goreportcard.com/report/github.com/oauth2-proxy/oauth2-proxy)
[![GoDoc](https://godoc.org/github.com/oauth2-proxy/oauth2-proxy?status.svg)](https://godoc.org/github.com/oauth2-proxy/oauth2-proxy)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/a58ff79407212e2beacb/maintainability)](https://codeclimate.com/github/oauth2-proxy/oauth2-proxy/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a58ff79407212e2beacb/test_coverage)](https://codeclimate.com/github/oauth2-proxy/oauth2-proxy/test_coverage)

A reverse proxy and static file server that provides authentication using Providers (Google, GitHub, and others)
to validate accounts by email, domain or group.

**Note:** This repository was forked from [bitly/OAuth2_Proxy](https://github.com/bitly/oauth2_proxy) on 27/11/2018.
Versions v3.0.0 and up are from this fork and will have diverged from any changes in the original fork.
A list of changes can be seen in the [CHANGELOG](CHANGELOG.md).

**Note:** This project was formerly hosted as `pusher/oauth2_proxy` but has been renamed as of 29/03/2020 to `oauth2-proxy/oauth2-proxy`.
Going forward, all images shall be available at `quay.io/oauth2-proxy/oauth2-proxy` and binaries will be named `oauth2-proxy`.

![Sign In Page](https://cloud.githubusercontent.com/assets/45028/4970624/7feb7dd8-6886-11e4-93e0-c9904af44ea8.png)

## Installation

1.  Choose how to deploy:

    a. Download [Prebuilt Binary](https://github.com/oauth2-proxy/oauth2-proxy/releases) (current release is `v7.4.0`)

    b. Build with `$ go install github.com/oauth2-proxy/oauth2-proxy/v7@latest` which will put the binary in `$GOROOT/bin`

    c. Using the prebuilt docker image [quay.io/oauth2-proxy/oauth2-proxy](https://quay.io/oauth2-proxy/oauth2-proxy) (AMD64, PPC64LE, ARMv6, ARMv8 and ARM64 available)

    Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.

    ```
    sha256sum -c sha256sum.txt 2>&1 | grep OK
    oauth2-proxy-x.y.z.linux-amd64: OK
    ```

2.  [Select a Provider and Register an OAuth Application with a Provider](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider)
3.  [Configure OAuth2 Proxy using config file, command line options, or environment variables](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/overview)
4.  [Configure SSL or Deploy behind a SSL endpoint](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/tls) (example provided for Nginx)


## Security

If you are running a version older than v6.0.0 we **strongly recommend you please update** to a current version.
See [open redirect vulnerability](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-5m6c-jp6f-2vcv) for details.

## Docs

Read the docs on our [Docs site](https://oauth2-proxy.github.io/oauth2-proxy/docs/).

![OAuth2 Proxy Architecture](https://cloud.githubusercontent.com/assets/45028/8027702/bd040b7a-0d6a-11e5-85b9-f8d953d04f39.png)

## Getting Involved

If you would like to reach out to the maintainers, come talk to us in the `#oauth2-proxy` channel in the [Gophers slack](http://gophers.slack.com/).

## Contributing

Please see our [Contributing](CONTRIBUTING.md) guidelines. For releasing see our [release creation guide](RELEASE.md).
