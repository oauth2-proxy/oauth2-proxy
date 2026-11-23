# Security Policy

## Reporting a Vulnerability

If you believe you have found a vulnerability in OAuth2 Proxy or one of its
dependencies, do not open a public GitHub issue or pull request, and do not
share details publicly. Please report it privately by emailing
[security@oauth2-proxy.dev](mailto:security@oauth2-proxy.dev).

OAuth2 Proxy is maintained by volunteers. We will investigate reports and
respond on a best-effort basis; this may take longer than projects with
dedicated, full-time security teams.

## What to Report

Please report vulnerabilities that have a demonstrable security impact in a
supported OAuth2 Proxy configuration. Insecure default configuration options
are not, by themselves, security vulnerabilities.

Do not report dependency CVEs solely because they appear in vulnerability scan
output. We monitor dependency scans, including GitHub's alerts, ourselves.
Reports of dependency vulnerabilities should explain how OAuth2 Proxy is
affected and include a reproducible exploit or other evidence of impact.

Please include as much detail as possible, ideally:

- A reproducible case that demonstrates the vulnerability
- How you discovered the vulnerability
- A potential fix, if you have one
- Affected versions, if the issue is not present in the main branch
- Your GitHub username

## Disclosure Process

We use [GitHub Security Advisories](https://docs.github.com/en/github/managing-security-vulnerabilities/about-github-security-advisories)
to discuss fixes privately. If you include your GitHub username, we can add you
as a collaborator so that you can participate in the discussion and validate
proposed fixes.

For minor issues and already-disclosed vulnerabilities, typically in
dependencies, we may use a regular pull request instead of a security advisory.

After agreeing on a fix, we will merge it and make a release. When several
security issues are in progress, we may wait until all patches are ready.
Backports to previous releases are at the maintainers' discretion.
