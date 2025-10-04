# OAuth2-Proxy Contributor Ladder

This document defines the roles, responsibilities, advancement criteria, 
inactivity process, and interim role policies for OAuth2-Proxy contributors. 
It extends the standard Kubernetes-style ladder with **specialty tracks** so 
contributors can grow within their focus areas.

---

## Roles

### 1) Contributor
Anyone making contributions of any kind (code, docs, tests, CI configs, security 
reports, reviews, triage, discussions).

**Requirements**
- For code changes all commits need to be Signed-Off by you. This is enforced
  through the [DCO GitHub App](https://github.com/apps/dco)
- Follow the OAuth2-Proxy/CNCF [Code of Conduct](CODE_OF_CONDUCT.md)

**Privileges**
- Recognized as an active community member
- Eligible for nomination to **Member**

---

### 2) Member
Regular contributors engaged with the project for at least **3 months**.

**Requirements**
- Self nomination by the contributor via a GitHub Issue.
- Must be Sponsored/Approved by **two Core Maintainers** (sponsorship ask must 
  happen within the GitHub issue by tagging the sponsors).
- Substantive contributions (code, docs, tests, reviews, triage) in the last 
  3 months.

**Privileges**
- Added to the GitHub `members` team.
- Can be assigned issues and PRs.
- Eligible for **Reviewer** nomination.

---

### 3) Reviewer (per Specialty)
Experienced contributors who review changes in **one or more specialties**.

**Requirements**
- Member for at least **3 months**.
- Regular, high-quality reviews in the specialty.
- Several meaningful Issue or PR reviews over the last 3 months.

**Privileges**
- Listed as `reviewer` in the relevant `OWNERS` files.
- May use `/lgtm` on PRs within the specialty.
- Eligible for **Maintainer** nomination.

> A contributor may hold different roles across specialties 
  (e.g., **Reviewer** in Provider Integrations, **Member** in Core Proxy).

---

### 4) Maintainer (Project-Wide)
Project leaders with governance, release, and cross-specialty responsibility.

**Requirements**
- Reviewer for at least **6 months** in one or more specialties.
- Demonstrated leadership, reliability, and constructive collaboration.
- Nominated and approved by a **simple majority** of Maintainers.

**Privileges**
- GitHub admin rights as needed.
- Release management authority.
- Representation within CNCF.

---

## Specialty Tracks

Specialties define scope for `reviewer` permissions and expectations.

### Core Proxy
Focus: Main proxy functionality, request handling, session management, 
authentication flow, and security implementation.

**Key Responsibilities:**
- Review core proxy changes in files like `oauthproxy.go`, `main.go`, and `validator.go`
- Ensure adherence to [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) 
  and [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) specifications
- Validate security implementations, including session management, token 
  validation, and secure cookie handling
- Review authentication and authorization flow implementations
- Ensure proper handling of edge cases and security vulnerabilities

### Provider Integrations
Focus: OAuth/OIDC provider integrations in the `providers/` directory.

**Key Responsibilities:**
- Review provider-specific code changes in the `providers/` directory
- Ensure conformance to OAuth/OIDC standards and provider-specific requirements
- Coordinate breaking changes for provider implementations
- Review provider configuration documentation
- Validate provider test implementations

### Configuration / API
Focus: Configuration options, API changes, and example configurations.

**Key Responsibilities:**
- Review configuration-related code and documentation
- Ensure backward compatibility of configuration options
- Review example configurations in the `contrib/` directory
- Validate CLI argument parsing and validation

### Helm Chart & Kubernetes
Focus: Helm chart in the separate `oauth2-proxy/manifests` repository and 
Kubernetes deployment configurations.

**Key Responsibilities:**
- Review Helm chart templates and values
- Ensure Kubernetes best practices in deployment configurations
- Validate Helm chart testing and CI integration
- Review Kubernetes-related documentation

### Documentation
Focus: Documentation in the `docs/` directory, including configuration guides, 
provider documentation, and tutorials.

**Key Responsibilities:**
- Review documentation changes for accuracy and clarity
- Ensure documentation is kept in sync with code changes
- Review provider-specific documentation
- Validate example configurations and tutorials
- Review versioning and release documentation

### CI / Automation
Focus: Test implementations and CI/CD workflows across repositories.

**Key Responsibilities:**
- Review integration and E2E tests
- Ensure adequate test coverage for new features
- Review CI/CD workflows in `.github/workflows/`
- Validate test infrastructure and test data
- Review test automation and reporting

### Community
Focus: Community nurturing, issue triage, and user support.

**Key Responsibilities:**
- Help with issue triage and support requests
- Monitor community channels (Slack, GitHub Discussions)
- Organize community talks and events
- Promote OAuth2-Proxy in the community
- Create demos and tutorials for users
- Foster a welcoming environment for new contributors

---

### Specialty Advancement

Contributors can advance in multiple specialties simultaneously. For example:

- A contributor could be a **Reviewer** in Provider Integrations and a **Member** in Core Proxy
- A contributor could be a **Reviewer** in both Helm Chart & Kubernetes and Testing & CI

This allows contributors to focus on areas where they have expertise while still contributing to other parts of the project.


---

## Member Abuse

Abuse of project resources is a serious violation of our community standards and 
will not be tolerated. This includes but is not limited to:

* Using project infrastructure for unauthorized activities.
* Misusing project funds or financial resources.
* Gaining unauthorized access to or damaging project infrastructure.
* Willingly engaging in activities that are against the Code of Conduct.
* Willingly introducing malware or viruses to the project's infrastructure or codebase.
* Any other activity that jeopardizes the project's resources, reputation, or community members.

### Procedure for Handling Abuse

1. **Immediate Revocation of Privileges**: If abuse is suspected, any maintainer 
  can immediately revoke the member's access to all project infrastructure and 
  resources to prevent further damage. This is a precautionary measure and not a 
  final judgment.

2. **Investigation**: The maintainers will conduct a private investigation to 
  gather all relevant facts and evidence. The accused member will be given an 
  opportunity to respond to the allegations.

3. **Decision**: Based on the investigation, the maintainers will determine if a 
  violation has occurred.

4. **Consequences**: If a violation is confirmed, consequences will be applied, 
  which may include:
   - Permanent removal from the project.
   - Reporting the user to GitHub and other relevant platforms.
   - In cases of financial misuse or illegal activities, reporting to law 
     enforcement authorities.

All actions taken will be documented. The privacy of all individuals involved 
will be respected throughout the process.

---

## Advancement Process

1. **Nomination** by an eligible community member (Member or Higher) via a GitHub issue.
2. **Sponsorship** by two role holders at the **target level or higher** (within the specialty where applicable).
3. **Review** of activity and behavior (quality, reliability, collaboration, responsiveness).
4. **Decision** by lazy consensus of the relevant group (or **simple majority** if contested).

---

## Inactivity

A **Reviewer** or **Maintainer** role holder may be considered inactive if they 
have not actively contributed or performed general project responsibilities for 
**six (6) consecutive months**.

### Measurement Sources
- GitHub activity: Merged PRs, PR reviews, issue triage/comments.
- Participation in community calls or asynchronous design discussions.

### Triggering Process
1. **Detection**
   - Activity is reviewed at least quarterly by Maintainers or via automation.
   - Any Maintainer may propose an inactivity review for a role holder.
2. **Notification**
   - A public issue is opened in a `community`/`governance` space (or email if sensitive).
   - The individual is tagged/emailed and given **30 days** to respond.
3. **Grace Period**
   - If the contributor indicates intent to return, no change is made.
   - If there is no response within the grace period, proceed.
4. **Decision**
   - Demotion is decided by **lazy consensus** of Maintainers, or **simple majority** if contested.
5. **Scope**
   - Demotion via inactivity fully removes the role holder from the organization.
6. **Documentation**
   - Update `OWNERS`, GitHub teams, and governance records.
   - Former Members may be listed as **Emeritus**.

### Reinstatement
A contributor can be reinstated at their previous level via the standard 
advancement process. Prior history is considered favorably.

---

## Emeritus Status
Emeritus status recognizes former Maintainers, Reviewers, or Members who have 
made substantial and lasting contributions to the OAuth2-Proxy project but are 
stepping down from active responsibilities.

Emeritus status is honorary and does not confer any formal responsibilities or 
authority.

### Purpose
* Honor and recognize long-term contributions.
* Preserve institutional knowledge and mentorship potential.
* Encourage continued engagement with the community without requiring full role responsibilities.

---

## Cross-References

- Project governance and decision-making: see [GOVERNANCE.md](GOVERNANCE.md)
- Specialty ownership: [CODEOWNERS](./.github/CODEOWNERS) files per directory
