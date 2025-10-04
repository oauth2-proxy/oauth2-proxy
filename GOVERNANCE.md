# OAuth2-Proxy Governance

This document defines the project governance for OAuth2-Proxy

## Overview

**OAuth2-Proxy** is a flexible, open-source tool that can act as either a 
standalone reverse proxy or a middleware component integrated into existing
reverse proxy or load balancer setups. It provides a simple and secure way to
protect your web applications with OAuth2 / OIDC authentication. As a reverse
proxy, it intercepts requests to your application and redirects users to an
OAuth2 provider for authentication. As a middleware, it can be seamlessly
integrated into your existing infrastructure to handle authentication for
multiple applications.

OAuth2-Proxy supports a lot of OAuth2 as well as OIDC providers. Either through
a generic OIDC client or a specific implementation for Google, Microsoft Entra ID,
GitHub, login.gov and others. Through specialised provider implementations
oauth2-proxy can extract more details about the user like preferred usernames
and groups. Those details can then be forwarded as HTTP headers to your 
upstream applications.

## Community Roles

- **Users**: Engineers and operators who deploy, configure, and maintain 
  OAuth2-Proxy in their environments. These are typically DevOps engineers, 
  SREs, or platform engineers who integrate OAuth2-Proxy with their 
  applications. End users who authenticate through OAuth2-Proxy typically do 
  not interact directly with OAuth2-Proxy
- **Contributors**: Anyone who makes contributions (code, docs, tests, reviews, 
  triage, discussions)
- **Reviewers / Maintainers**: Governance roles with defined responsibilities, 
  privileges, and promotion processes described in the [Contributor Ladder](CONTRIBUTOR_LADDER.md)

Maintainers are project leaders responsible for overall health, technical 
direction, and release management.

---

## Maintainers

### Core Maintainers
Core Maintainers are a subset of Maintainers who have been with the project for 
an extended period and have demonstrated consistent technical leadership and 
commitment. They are responsible for major project decisions, including 
governance changes and maintainer appointments.

### Expectations
Maintainers are expected to:
- Review pull requests, triage issues, and fix bugs in their areas of expertise
- Monitor community channels and help users and contributors
- Respond to time-sensitive security issues
- Follow the decision-making processes described in this document and in the 
  Contributor Ladder

If a maintainer cannot fulfill these duties, they should move to **Emeritus** 
status. Maintainers may also be moved to Emeritus via the decision-making process.

### Adding or Removing Maintainers
- **Addition**: A candidate is nominated by an existing maintainer and elected 
  by a **simple majority** of current maintainers
- **Removal**: Removal requires a **simple majority** of current maintainers
- **Company voting**: Votes to nominate maintainers by contributors belonging 
  to the same employer count as **one** collective vote.

---

## Voting Eligibility

Voting rights vary by decision type:

| Decision Type                                  | Eligible Voters                              |
|------------------------------------------------|----------------------------------------------|
| **Governance changes**                         | Core Maintainers                             |
| **Adding/removing Maintainers**                | Core Maintainers                             |
| **Technical decisions within a specialty**     | All Reviewers and Maintainers                |
| **Project-wide technical direction**           | All Maintainers                              |
| **Security incident decisions**                | All Maintainers                              |

**Notes:**
- Company voting limits apply: maintainers/reviewers from the same declared 
  employer have **one** combined vote
- If maintainers/reviewers from the same declared employer cannot reach
  consensus for their vote, that employer's vote is recorded as **abstain**

---

## Decision Making

OAuth2-Proxy strives for **consensus** via open discussion. When consensus 
cannot be reached, any eligible voter may call a vote.

- **Simple Majority**: More than 50% of eligible voters in the group
- **Venues**: Votes may occur on GitHub, email, Slack, community meetings, or a 
  suitable voting service
- **Ballots**: "Agree/+1", "Disagree/-1", or "Abstain" (counts as no vote)

---

## Contributing Changes

The process of reviewing proposed changes differs depending on the size and
impact of the change.

### Minor Changes
A minor change is a bug fix, a smaller enhancement or a smaller addition to 
existing features.

To propose a minor change, simply create an issue in our [Issue Tracker](https://github.com/oauth2-proxy/oauth2-proxy/issues) or directly create a pull request.

A maintainer will be responsible for ultimately approving the pull request. The 
maintainer may do a deep review of the pull request or delegate to an expert in 
the corresponding area.

If the change has a bigger impact it has to follow the process for larger 
changes.

### Larger Changes
For larger changes all maintainers and contributors should have a chance of 
reviewing the change. Therefore larger changes require an RFC to be created 
through the [Issue Tracker](https://github.com/oauth2-proxy/oauth2-proxy/issues).

If there are any objections to the change they can in most cases be resolved 
through discussions in the corresponding issue or pull request. If a resolution 
can not be made it can be accepted if at least 2/3 of maintainers approve the 
change.

---

## Lazy Consensus

OAuth2-Proxy uses [Lazy Consensus](http://en.osswiki.info/concepts/lazy_consensus) for most decisions.

- PRs and proposals should allow **at least eight (8) working days** for comments
- Other maintainers may request additional time when justified and commit to a 
  timely review

**Exclusions** (lazy consensus does **not** apply):
- Removal of maintainers
- Any substantive governance changes

---

## Updating Governance

Substantive changes to this document require a **simple majority** of Core Maintainers.

---

## Contributor Pathways & Specialties

Advancement pathways, responsibilities, privileges, and specialty areas are 
defined in the [Contributor Ladder](CONTRIBUTOR_LADDER.md).

---

## Security

OAuth2-Proxy follows responsible disclosure practices. Security-impacting 
issues should be reported via the documented security contact channels 
(see `SECURITY.md` if present or repository Security tab). Security fixes may
be handled privately until a coordinated disclosure and release are ready.

---

## CNCF Alignment

OAuth2-Proxy governance aims for open, transparent, and vendor-neutral operation 
consistent with CNCF expectations. The [Contributor Ladder](CONTRIBUTOR_LADDER.md) 
provides clear pathways for community members to grow into leadership.
