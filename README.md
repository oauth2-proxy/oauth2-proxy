[![Continuous Integration](https://github.com/oauth2-proxy/oauth2-proxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/oauth2-proxy/oauth2-proxy/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/oauth2-proxy/oauth2-proxy)](https://goreportcard.com/report/github.com/oauth2-proxy/oauth2-proxy)
[![GoDoc](https://godoc.org/github.com/oauth2-proxy/oauth2-proxy?status.svg)](https://godoc.org/github.com/oauth2-proxy/oauth2-proxy)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/a58ff79407212e2beacb/maintainability)](https://codeclimate.com/github/oauth2-proxy/oauth2-proxy/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a58ff79407212e2beacb/test_coverage)](https://codeclimate.com/github/oauth2-proxy/oauth2-proxy/test_coverage)

![OAuth2 Proxy](docs/static/img/logos/OAuth2_Proxy_horizontal.svg)

OAuth2-Proxy is a flexible, open-source tool that can act as either a standalone reverse proxy or a middleware component integrated into existing reverse proxy or load balancer setups. It provides a simple and secure way to protect your web applications with OAuth2 / OIDC authentication. As a reverse proxy, it intercepts requests to your application and redirects users to an OAuth2 provider for authentication. As a middleware, it can be seamlessly integrated into your existing infrastructure to handle authentication for multiple applications.

OAuth2-Proxy supports a lot of OAuth2 as well as OIDC providers. Either through a generic OIDC client or a specific implementation for Google, Microsoft Entra ID, GitHub, login.gov and others. Through specialised provider implementations oauth2-proxy can extract more details about the user like preferred usernames and groups. Those details can then be forwarded as HTTP headers to your upstream applications.

![Simplified Architecture](docs/static/img/simplified-architecture.svg)

## Get Started

OAuth2-Proxy's [Installation Docs](https://oauth2-proxy.github.io/oauth2-proxy/installation) cover how to install and configure your setup. Additionally you can take a further look at the [example setup files](https://github.com/oauth2-proxy/oauth2-proxy/tree/master/contrib/local-environment).

## Releases

### Binaries
We publish oauth2-proxy as compiled binaries on GitHub for all major architectures as well as more exotic ones like `ppc64le` as well as `s390x`.

Check out the [latest release](https://github.com/oauth2-proxy/oauth2-proxy/releases/latest).

### Images

From `v7.6.0` and up the base image has been changed from Alpine to [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless).
This image comes with even fewer installed dependencies and thus should improve security. The image therefore is also slightly smaller than Alpine.
For debugging purposes (and those who really need it. e.g. `armv6`) we still provide images based on Alpine. The tags of these images are suffixed with `-alpine`.

Since 2023-11-18 we build nightly images directly from the `master` branch and provide them at `quay.io/oauth2-proxy/oauth2-proxy-nightly`.
These images are considered unstable and therefore should **NOT** be used for production purposes unless you know what you're doing.

## Sponsors

![Microsoft](https://upload.wikimedia.org/wikipedia/commons/9/96/Microsoft_logo_%282012%29.svg)
Microsoft Azure credits for open source projects

Would you like to sponsor the project then please contact us at [sponsors@oauth2-proxy.dev](mailto:sponsors@oauth2-proxy.dev)

## Getting Involved
[![Slack](https://img.shields.io/badge/slack-Gopher_%23oauth2--proxy-red?logo=slack)](https://gophers.slack.com/archives/CM2RSS25N)

Join the #oauth2-proxy [Slack channel](https://gophers.slack.com/archives/CM2RSS25N) to chat with other users of oauth2-proxy or reach out to the maintainers directly. Use the [public invite link](https://invite.slack.golangbridge.org/) to get an invite for the Gopher Slack space.

OAuth2-Proxy is a community-driven project. We rely on the contribut️ions of our users to continually improve it. While review times can vary, we appreciate your patience and understanding. As a volunteer-driven project, we strive to keep this project stable and might take longer to merge changes.

If you want to contribute to the project. Please see our [Contributing](https://oauth2-proxy.github.io/oauth2-proxy/community/contribution) guide.

Who uses OAuth2-Proxy? Have a look at our new [ADOPTERS](ADOPTERS.md) file and
feel free to open a PR to add your organisation.

Thanks to all the people who already contributed ❤

<a href="https://github.com/oauth2-proxy/oauth2-proxy/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=oauth2-proxy/oauth2-proxy&columns=15&max=75" />
  <img src="https://img.shields.io/github/contributors/oauth2-proxy/oauth2-proxy" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

## Security

If you believe you have found a vulnerability within OAuth2 Proxy or any of its dependencies, please do **NOT** open an issue or PR on GitHub, please do **NOT** post any details publicly.

Security disclosures **MUST** be done in private. If you have found an issue that you would like to bring to the attention of the maintainers, please compose an email and send it to the list of people listed in our [MAINTAINERS](MAINTAINERS) file.

For more details read our full [Security Docs](https://oauth2-proxy.github.io/oauth2-proxy/community/security#security-disclosures)

### Security Notice for v6.0.0 and older

If you are running a version older than v6.0.0 we **strongly recommend** to the current version.

See [open redirect vulnerability](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-5m6c-jp6f-2vcv) for details.

## Repository History

**2018-11-27:** This repository was forked from [bitly/OAuth2_Proxy](https://github.com/bitly/oauth2_proxy). Versions v3.0.0 and up are from this fork and will have diverged from any changes in the original fork. A list of changes can be seen in the [CHANGELOG](CHANGELOG.md).

**2020-03-29:** This project was formerly hosted as `pusher/oauth2_proxy` but has been renamed to `oauth2-proxy/oauth2-proxy`. Going forward, all images shall be available at `quay.io/oauth2-proxy/oauth2-proxy` and binaries will be named `oauth2-proxy`.

## License

OAuth2-Proxy is distributed under [The MIT License](LICENSE).
