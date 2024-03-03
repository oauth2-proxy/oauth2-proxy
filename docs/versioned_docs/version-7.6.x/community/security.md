---
id: security
title: Security
---

:::note
OAuth2 Proxy is a community project.
Maintainers do not work on this project full time, and as such,
while we endeavour to respond to disclosures as quickly as possible,
this may take longer than in projects with corporate sponsorship.
:::

## Security Disclosures

:::important
If you believe you have found a vulnerability within OAuth2 Proxy or any of its
dependencies, please do NOT open an issue or PR on GitHub, please do NOT post
any details publicly.
:::

Security disclosures MUST be done in private.
If you have found an issue that you would like to bring to the attention of the
maintenance team for OAuth2 Proxy, please compose an email and send it to the
list of maintainers in our [MAINTAINERS](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/MAINTAINERS) file.

Please include as much detail as possible.
Ideally, your disclosure should include:
- A reproducible case that can be used to demonstrate the exploit
- How you discovered this vulnerability
- A potential fix for the issue (if you have thought of one)
- Versions affected (if not present in master)
- Your GitHub ID

### How will we respond to disclosures?

We use [GitHub Security Advisories](https://docs.github.com/en/github/managing-security-vulnerabilities/about-github-security-advisories)
to privately discuss fixes for disclosed vulnerabilities.
If you include a GitHub ID with your disclosure we will add you as a collaborator
for the advisory so that you can join the discussion and validate any fixes
we may propose.

For minor issues and previously disclosed vulnerabilities (typically for
dependencies), we may use regular PRs for fixes and forego the security advisory.

Once a fix has been agreed upon, we will merge the fix and create a new release.
If we have multiple security issues in flight simultaneously, we may delay
merging fixes until all patches are ready.
We may also backport the fix to previous releases,
but this will be at the discretion of the maintainers.
