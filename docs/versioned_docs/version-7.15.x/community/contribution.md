---
id: contribution
title: Becoming a Contributor
---

OAuth2 Proxy protects applications across thousands of production environments. We see over half a billion container pulls a year on [Quay.io](https://quay.io/repository/oauth2-proxy/oauth2-proxy). Its a small project with a large impact.

We are run by a small volunteer maintainer group. Our day-to-day focus is keeping the lights on: reviewing security fixes, patching CVEs, and resolving critical bugs. To build beyond maintenance mode and ship key architectural milestones, we actively need new contributors.

## Where we need help

You do not need deep Go internals experience to make a meaningful difference. The areas below represent our highest community needs today.

### Documentation

Clear docs save hours for thousands of operators. We need help with:

- **How-to guides**: Practical step-by-step tutorials for real production deployments.
- **Integration guides**: Setting up OAuth2 Proxy with popular reverse proxies and load balancers (e.g., NGINX, Traefik, Caddy, Kubernetes ingress controllers and more).
- **Structure and examples**: Improving overall navigation, fixing stale options and adding verified configuration examples for common setups.
- **Blog Posts**: Use-case / config show cases with demonstrated impact of the project.

### Issue and PR triage

Review bandwidth is our biggest bottleneck. You can help triage incoming issues and pull requests by:

- Reproducing reported bugs against current releases.
- Asking for missing logs, minimal reproduction configs, and provider details.
- Reviewing pull requests and verifying their test coverage.
- Applying appropriate categorization labels with Prow bot commands.
- Feel free to get in touch to get an idea where the most help is needed.

### End-to-end (E2E) testing

We want to revive our automated end-to-end test suite. We need help building and verifying those tests that spin up providers (Keycloak, Dex, mock OIDC servers) and upstream services to verify session lifecycles, cookie handling and header injection end-to-end.

## Automation and triage labels (Prow)

We use [Prow GitHub Actions](https://github.com/cncf/prow-github-actions) for workflow automation and issue triage. Anyone can help classify issues and pull requests by leaving comment commands.

Each command must be on its own line in a comment:

- `/kind <value>`: Classify the nature of the issue or PR.
  - Allowed: `bug`, `enhancement`, `documentation`, `refactor`, `test`, `breaking-change`
- `/area <value>`: Identify the component affected.
  - Allowed: `core`, `authentication`, `authorization`, `session`, `cookies`, `upstream`, `proxy`, `provider`, `configuration`, `api`, `documentation`, `ci`, `testing`, `docker`, `release`, `security`
- `/provider <value>`: Identify a specific identity provider implementation.
  - Allowed: `adfs`, `azure`, `bitbucket`, `cidaas`, `digitalocean`, `facebook`, `gitea`, `github`, `gitlab`, `google`, `keycloak`, `linkedin`, `logingov`, `ms-entra-id`, `nextcloud`, `oidc`, `sourcehut`
- `/assign` and `/unassign`: Claim or release ownership of an issue or PR.
- `/help`: Add the `help wanted` label to signal that assistance is welcomed.

Pull requests require a valid `kind/<value>` label before they can merge. If you see an unclassified PR, help out by adding one with `/kind`.

## Roadmap and project focus

Understanding our current focus will help you align PRs with overall direction:

### Maintenance baseline

Because our maintainer capacity is limited, security patches and critical bug fixes always come first! Changes that keep the project secure, stable and compliant take priority in reviews. And therefore other PRs might stay open or unreviewed for a long time.

### v8 focus

The upcoming v8 major release modernizes configuration and observability:

- **Structured YAML configuration**: Promoting the alpha YAML configuration to beta and stable. All ~160 configuration flags have been migrated from legacy TOML and CLI flags to a structured YAML schema.
- **Expressive enums**: Replacing ambiguous boolean flags with speaking enum values that make intent clear.
- **Structured contextual logging**: Adopting the `logr` abstraction with `zerolog` as the logging backend for consistent, structured log output across components in our codebase.

### Midterm focus (v8 and beyond)

Looking past v8, we want to align more closely with the official OAuth2 and OIDC specifications and simplify the architecture:

- **Spec-driven development**: Tracking additions and missing features from current OAuth 2.0, OAuth 2.1, and OpenID Connect specifications.
- **Expanded OAuth 2.0 flows**: Improving support for additional grant types and authorization flows.
- **Generic OAuth 2.0 support**: Today, pure OAuth 2.0 without OIDC discovery is not guaranteed to work reliably. We plan to separate OAuth 2.0 and OIDC flows cleanly and introduce a generic OAuth 2.0 provider implementation.
- **Clarifying project scope**: Clarifying what OAuth 2 Proxy is (an authentication proxy and identity forwarder) and what it is not (a full authorization policy engine). We would liek to remove unnecessary complexity.

## Getting started

Ready to contribute? Here is how to get involved:

1. **Join the community call**: Find the meeting schedule and details on our [homepage](https://www.oauth2-proxy.dev).
2. **Chat with us on Slack**: Join the `#oauth2-proxy` channel on the [CNCF Slack workspace](https://cloud-native.slack.com/archives/C098Y5URZ2N) (get an invite at [slack.cncf.io](https://slack.cncf.io/)).
3. **Read the setup guide**: Check the repository [CONTRIBUTING.md](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/CONTRIBUTING.md) for local development setup and our AI-use guidelines.
4. **Pick an issue**: Look for issues with the `help wanted` or `good first issue` labels on GitHub, or jump into PR triage.
