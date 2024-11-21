# Vx.x.x (Pre-release)

## Release Highlights

## Important Notes

## Breaking Changes

## Changes since v7.7.1

- [#2800](https://github.com/oauth2-proxy/oauth2-proxy/pull/2800) Add some opencontainer labels to docker image (@halkeye)
- [#2755](https://github.com/oauth2-proxy/oauth2-proxy/pull/2755) feat: add X-Envoy-External-Address as supported header (@bjencks)
- [#1985](https://github.com/oauth2-proxy/oauth2-proxy/pull/1985) Add support for systemd socket (@isodude)
- [#2300](https://github.com/oauth2-proxy/oauth2-proxy/pull/2300) Add fix for websocket path rewrite (@rekup)
- [#2821](https://github.com/oauth2-proxy/oauth2-proxy/pull/2821) feat: add CF-Connecting-IP as supported real ip header (@ondrejsika)
- [#2620](https://github.com/oauth2-proxy/oauth2-proxy/pull/2620) fix: update code_verifier to use recommended method (@vishvananda)
- [#2392](https://github.com/oauth2-proxy/oauth2-proxy/pull/2392) chore: extend test cases for oidc provider and documentation regarding implicit setting of the groups scope when no scope was specified in the config (@jjlakis / @tuunit)

# V7.7.1

## Release Highlights

- 🐛 Several bugs have been squashed

## Important Notes

## Breaking Changes

## Changes since v7.7.0

- [#2803](https://github.com/oauth2-proxy/oauth2-proxy/pull/2803) fix: self signed certificate handling in v7.7.0 (@tuunit)
- [#2619](https://github.com/oauth2-proxy/oauth2-proxy/pull/2619) fix: unable to use hyphen in JSON path for oidc-groups-claim option (@rd-danny-fleer)
- [#2311](https://github.com/oauth2-proxy/oauth2-proxy/pull/2311) fix: runtime error: index out of range (0) with length 0 (@miguelborges99 / @tuunit)

# V7.7.0

## Release Highlights

- 🌐 Custom user agent "oauth2-proxy/<version>"
- 💾 Added s390x architecture support
- 🕵️‍♀️ Vulnerabilities have been addressed
  - CVE-2024-24786
  - CVE-2024-24791
  - CVE-2024-24790
  - CVE-2024-24784
- 📖 Improved docs

## Important Notes
- Remove support of arm/v6 for distroless image runtime. Alpine tags still support arm/v6.

## Breaking Changes

## Changes since v7.6.0

- [#2539](https://github.com/oauth2-proxy/oauth2-proxy/pull/2539) pkg/http: Fix leaky test (@isodude)
- [#4917](https://github.com/oauth2-proxy/oauth2-proxy/pull/4917) Upgraded all modules to the latest version (@pierluigilenoci)
- [#2570](https://github.com/oauth2-proxy/oauth2-proxy/pull/2570) Set default user agent to oauth2-proxy/$version (from default Golang one)
- [#2674](https://github.com/oauth2-proxy/oauth2-proxy/pull/2674) docs: additional notes about available claims for HeaderValue (@vegetablest)
- [#2459](https://github.com/oauth2-proxy/oauth2-proxy/pull/2459) chore(deps): Updated to ginkgo v2 (@kvanzuijlen, @tuunit)
- [#2112](https://github.com/oauth2-proxy/oauth2-proxy/pull/2112) docs: update list of providers which support refresh tokens (@mikefab-msf)
- [#2734](https://github.com/oauth2-proxy/oauth2-proxy/pull/2734) Added s390x architecture option support (@priby05)
- [#2589](https://github.com/oauth2-proxy/oauth2-proxy/pull/2589) Added support for regex path matching and rewriting when using a static `file:` upstream (@ianroberts)
- [#2790](https://github.com/oauth2-proxy/oauth2-proxy/pull/2790) chore(deps): update all golang dependencies (@tuunit)
- [#2607](https://github.com/oauth2-proxy/oauth2-proxy/pull/2607) fix(csrf): fix possible infinite loop (@Primexz)

# V7.6.0

## Release Highlights

## Important Notes

## Breaking Changes

## Changes since v7.5.1

- [#2381](https://github.com/oauth2-proxy/oauth2-proxy/pull/2381) Allow username authentication to Redis cluster (@rossigee)
- [#2345](https://github.com/oauth2-proxy/oauth2-proxy/pull/2345) Log error details when failed loading CSRF cookie (@charvadzo)
- [#2128](https://github.com/oauth2-proxy/oauth2-proxy/pull/2128) Update dependencies (@vllvll)
- [#2269](https://github.com/oauth2-proxy/oauth2-proxy/pull/2269) Added Azure China (and other air gaped cloud) support (@mblaschke)
- [#2237](https://github.com/oauth2-proxy/oauth2-proxy/pull/2237) adds an option to append CA certificates (@emsixteeen)
- [#2128](https://github.com/oauth2-proxy/oauth2-proxy/pull/2128) Update dependencies (@vllvll)
- [#2239](https://github.com/oauth2-proxy/oauth2-proxy/pull/2312) Add possibility to encode the state param as UrlEncodedBase64 (@brezinajn)
- [#2274](https://github.com/oauth2-proxy/oauth2-proxy/pull/2274) Upgrade golang.org/x/net to v0.17.0 (@pierluigilenoci)
- [#2278](https://github.com/oauth2-proxy/oauth2-proxy/pull/2278) Improve the Nginx auth_request example (@akunzai)
- [#2282](https://github.com/oauth2-proxy/oauth2-proxy/pull/2282) Fixed checking Google Groups membership using Google Application Credentials (@kvanzuijlen)
- [#2183](https://github.com/oauth2-proxy/oauth2-proxy/pull/2183) Allowing relative redirect url though an option (@axel7083)
- [#1866](https://github.com/oauth2-proxy/oauth2-proxy/pull/1866) Add support for unix socker as upstream (@babs)
- [#1876](https://github.com/oauth2-proxy/oauth2-proxy/pull/1876) Add `--backend-logout-url` with `{id_token}` placeholder (@babs)
- [#1949](https://github.com/oauth2-proxy/oauth2-proxy/pull/1949) Allow cookie names with dots in redis sessions (@miguelborges99)
- [#2297](https://github.com/oauth2-proxy/oauth2-proxy/pull/2297) Add nightly build and push (@tuunit)
- [#2329](https://github.com/oauth2-proxy/oauth2-proxy/pull/2329) Add an option to skip request to profile URL for resolving missing claims in id_token (@nilsgstrabo)
- [#2299](https://github.com/oauth2-proxy/oauth2-proxy/pull/2299) bugfix: OIDCConfig based providers are not respecting flags and configs (@tuunit)
- [#2343](https://github.com/oauth2-proxy/oauth2-proxy/pull/2343) chore: Added checksums for .tar.gz (@kvanzuijlen)
- [#2248](https://github.com/oauth2-proxy/oauth2-proxy/pull/2248) Added support for semicolons in query strings. (@timwsuqld)
- [#2196](https://github.com/oauth2-proxy/oauth2-proxy/pull/2196) Add GitHub groups (orgs/teams) support. Including `X-Forwarded-Groups` header (@tuunit)
- [#2371](https://github.com/oauth2-proxy/oauth2-proxy/pull/2371) Remove nsswitch DNS resolution workaround (@tuunit)
- [#2295](https://github.com/oauth2-proxy/oauth2-proxy/pull/2295) Change base-image to [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless) (@kvanzuijlen)
- [#2356](https://github.com/oauth2-proxy/oauth2-proxy/pull/2356) Update go-jose dependency (@dasvh)
- [#2357](https://github.com/oauth2-proxy/oauth2-proxy/pull/2357) Update ojg to latest release (@bitfehler)
- [#1922](https://github.com/oauth2-proxy/oauth2-proxy/pull/1922) Added support for env variables in the alpha struct (@hevans-dglcom)
- [#2235](https://github.com/oauth2-proxy/oauth2-proxy/pull/2235) Bump golang to 1.21 and min allowed version to 1.20 (@tuunit)

# V7.5.1

## Release Highlights
- 🐛 Several bugs have been squashed
- 🕵️‍♀️ Vulnerabilities have been addressed
- 📖Improved docs

## Important Notes

- This release includes fixes for a number of CVEs, we recommend to upgrade as soon as possible.
- The environment variable OAUTH2_PROXY_GOOGLE_GROUP has been deprecated in favor of OAUTH2_PROXY_GOOGLE_GROUPS. Next major release
will remove this option. This change makes sure that the configuration options follow the documentation.

## Breaking Changes

N/A

## Changes since v7.5.0
- [#2220](https://github.com/oauth2-proxy/oauth2-proxy/pull/2220) Added binary and docker release platforms (@kvanzuijlen)
- [#2221](https://github.com/oauth2-proxy/oauth2-proxy/pull/2221) Backwards compatible fix for wrong environment variable name (OAUTH2_PROXY_GOOGLE_GROUPS) (@kvanzuijlen)
- [#1989](https://github.com/oauth2-proxy/oauth2-proxy/pull/1989) Fix default scope for keycloak-oidc provider (@tuunit)
- [#2217](https://github.com/oauth2-proxy/oauth2-proxy/pull/2217) Upgrade alpine to version 3.18 (@polarctos)
- [#2208](https://github.com/oauth2-proxy/oauth2-proxy/pull/2208) Improved session documentation (@lathspell)
- [#2229](https://github.com/oauth2-proxy/oauth2-proxy/pull/2229) bugfix: default scopes for OIDCProvider based providers (@tuunit)
- [#2194](https://github.com/oauth2-proxy/oauth2-proxy/pull/2194) Fix Gitea token validation (@tuunit)

# V7.5.0

## Release Highlights
- 🐛 Several bugs have been squashed
- 🕵️‍♀️ Vulnerabilities have been addressed
- ⭐️ Added a readiness endpoint to check if the application is ready to receive traffic
- ⭐️ Google Application Default Credentials support (i.e. for running on Google Cloud Platform)
- ⭐ Session cookie support

## Important Notes

- This release includes fixes for a number of CVEs, we recommend to upgrade as soon as possible.
- This release was pushed with the wrong Docker platform type for arm64/armv8. Use v7.5.1 instead.
- This release introduced a bug with the Keycloak OIDC provider causing no scopes to be send along with the request. Use v7.5.1 instead.

## Breaking Changes
The following PR introduces a change to how auth routes are evaluated using the flags `skip-auth-route`/`skip-auth-regex`. The new behaviour uses the regex you specify to evaluate the full path including query parameters. For more details please read the detailed description [#2271](https://github.com/oauth2-proxy/oauth2-proxy/issues/2271)
- [#2192](https://github.com/oauth2-proxy/oauth2-proxy/pull/2192) Use X-Forwarded-Uri if it exists for pathRegex match (@mzndr / @jawys)

## Changes since v7.4.0
- [#2028](https://github.com/oauth2-proxy/oauth2-proxy/pull/2028) Update golang.org/x/net to v0.7.0 ato address GHSA-vvpx-j8f3-3w6h (@amrmahdi)
- [#1873](https://github.com/oauth2-proxy/oauth2-proxy/pull/1873) Fix empty users with some OIDC providers (@babs)
- [#1882](https://github.com/oauth2-proxy/oauth2-proxy/pull/1882) Make `htpasswd.GetUsers` racecondition safe (@babs)
- [#1883](https://github.com/oauth2-proxy/oauth2-proxy/pull/1883) Ensure v8 manifest variant is set on docker images (@braunsonm)
- [#1906](https://github.com/oauth2-proxy/oauth2-proxy/pull/1906) Fix PKCE code verifier generation to never use UTF-8 characters (@braunsonm)
- [#1839](https://github.com/oauth2-proxy/oauth2-proxy/pull/1839) Add readiness checks for deeper health checks (@kobim)
- [#1927](https://github.com/oauth2-proxy/oauth2-proxy/pull/1927) Fix default scope settings for none oidc providers (@tuunit)
- [#1713](https://github.com/oauth2-proxy/oauth2-proxy/pull/1713) Add session cookie support (@t-katsumura @tanuki884)
- [#1951](https://github.com/oauth2-proxy/oauth2-proxy/pull/1951) Fix validate URL, check if query string marker (?) or separator (&) needs to be appended (@miguelborges99)
- [#1920](https://github.com/oauth2-proxy/oauth2-proxy/pull/1920) Make sure emailClaim is not overriden if userIDClaim is not set (@mdreem)
- [#2010](https://github.com/oauth2-proxy/oauth2-proxy/pull/2010) Log the difference between invalid email and not authorized session (@omBratteng)
- [#1988](https://github.com/oauth2-proxy/oauth2-proxy/pull/1988) Ensure sign-in page background is uniform throughout the page (@corybolar)
- [#2013](https://github.com/oauth2-proxy/oauth2-proxy/pull/2013) Upgrade alpine to version 3.17.2 and library dependencies (@miguelborges99)
- [#2047](https://github.com/oauth2-proxy/oauth2-proxy/pull/2047) CVE-2022-41717: DoS in Go net/http may lead to DoS (@miguelborges99)
- [#2126](https://github.com/oauth2-proxy/oauth2-proxy/pull/2126) Added support for GKE Workload Identity (@kvanzuijlen)
- [#1921](https://github.com/oauth2-proxy/oauth2-proxy/pull/1921) Check jsonpath syntax before interpretation (@eloo-abi)
- [#2025](https://github.com/oauth2-proxy/oauth2-proxy/pull/2025) Embed static stylesheets and dependencies (@corybolar)

# V7.4.0

## Release Highlights

- New Azure groups support for Azure OAuth2 v2.0
- Option to configure API routes - paths that will not redirect to login when unauthenticated
- CSRF and session cookies now have different timeouts

## Important Notes

- [#1708](https://github.com/oauth2-proxy/oauth2-proxy/pull/1708) Enable different CSRF cookies per request (@miguelborges99)
  - Since the CSRF cookie name is now longer it could potentially break long cookie names (around 1000 characters).
  - Having a unique CSRF cookie per request can lead to quite a number of cookies, in case an application performs a high number of parallel authentication requests. Each call will redirect to /oauth2/start, if the user is not authenticated, and a new cookie will be set. The successfully authenticated requests will have its CSRF cookies immediatly expired, however the failed ones will mantain its CSRF cookies until they expire (by default in 15 minutes).
  - The user may redefine the CSRF cookie expiration time using flag "--cookie-csrf-expire" (e.g. --cookie-csrf-expire=5m). By default, it is 15 minutes, but you can fine tune to your environment.
- [#1574](https://github.com/oauth2-proxy/oauth2-proxy/pull/1574) Add Azure groups support and Azure OAuth v2.0 (@adriananeci)
  - group membership check is now validated while using the the azure provider.
  - Azure OAuth v2.0 (https://login.microsoftonline.com/{tenant_id}/v2.0) is now available along with Azure OAuth v1.0. See https://github.com/oauth2-proxy/oauth2-proxy/blob/master/docs/docs/configuration/auth.md#azure-auth-provider for more details
  - When using v2.0 Azure Auth endpoint (`https://login.microsoftonline.com/{tenant-id}/v2.0`) as `--oidc_issuer_url`, in conjunction with `--resource` flag, be sure to append `/.default` at the end of the resource name. See https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#the-default-scope for more details.
- This release includes fixes for a number of CVEs, we recommend to upgrade as soon as possible.

## Breaking Changes

N/A

## Changes since v7.3.0

- [#1862](https://github.com/oauth2-proxy/oauth2-proxy/pull/1862) Update dependencies (@JoelSpeed)
- [#1828](https://github.com/oauth2-proxy/oauth2-proxy/pull/1828) call providerData.setProviderDefaults for oidc provider to achieve consistent behaviour (@centzilius)
  - UserClaim will be set to sub instead of beeing empty from now on.
- [#1691](https://github.com/oauth2-proxy/oauth2-proxy/pull/1691) Fix Redis IdleTimeout when Redis timeout option is set to non-zero (@dimss)
- [#1669](https://github.com/oauth2-proxy/oauth2-proxy/pull/1699) Fix method deprecated error in lint (@t-katsumura)
- [#1701](https://github.com/oauth2-proxy/oauth2-proxy/pull/1701) Watch the htpasswd file for changes and update the htpasswdMap (@aiciobanu)
- [#1709](https://github.com/oauth2-proxy/oauth2-proxy/pull/1709) Show an alert message when basic auth credentials are invalid (@aiciobanu)
- [#1723](https://github.com/oauth2-proxy/oauth2-proxy/pull/1723) Added ability to specify allowed TLS cipher suites. (@crbednarz)
- [#1720](https://github.com/oauth2-proxy/oauth2-proxy/pull/1720) Extract roles from authToken, to allow using allowed roles with Keycloak. (@MrDeerly )
- [#1774](https://github.com/oauth2-proxy/oauth2-proxy/pull/1774) Fix vulnerabilities CVE-2022-27191, CVE-2021-44716 and CVE-2022-29526. (@felipeconti)
- [#1667](https://github.com/oauth2-proxy/oauth2-proxy/issues/1667) Rename configuration file flag for PKCE (@ChrisEke)
to remain consistent with CLI flags. You should specify `code_challenge_method` in your configuration instead of
`force_code_challenge_method`.
- [#1708](https://github.com/oauth2-proxy/oauth2-proxy/pull/1708) Enable different CSRF cookies per request (@miguelborges99)
  - Add flag "--cookie-csrf-per-request" which activates an algorithm to name CSRF cookies differently per request.
    This feature allows parallel callbacks and by default it is disabled.
  - Add flag "--cookie-csrf-expire" to define a different expiration time for the CSRF cookie. By default, it is 15 minutes.
- [#1762](https://github.com/oauth2-proxy/oauth2-proxy/pull/1762) Support negating for skip auth routes (@ianldge)
- [#1788](https://github.com/oauth2-proxy/oauth2-proxy/pull/1788) Update base docker image to alpine 3.16 (@tooptoop4)
- [#1760](https://github.com/oauth2-proxy/oauth2-proxy/pull/1760) Option to configure API routes (@segfault16)
- [#1825](https://github.com/oauth2-proxy/oauth2-proxy/pull/1825) Fix vulnerabilities CVE-2022-32149 and CVE-2022-27664. (@crbednarz)
- [#1750](https://github.com/oauth2-proxy/oauth2-proxy/pull/1750) Fix Nextcloud provider (@n1tehawk)
- [#1574](https://github.com/oauth2-proxy/oauth2-proxy/pull/1574) Add Azure groups support and Azure OAuth v2.0 (@adriananeci)
- [#1851](https://github.com/oauth2-proxy/oauth2-proxy/pull/1851) Bump golang to 1.19 and min allowed version to 1.18 (@adriananeci)
- [#1815](https://github.com/oauth2-proxy/oauth2-proxy/pull/1815) Keycloak: save user and preferredUsername in session to populate headers for the backend (@babs)
- [#1847](https://github.com/oauth2-proxy/oauth2-proxy/pull/1847) Update go-redis/redis to v9 (@arhamGH)
-
# V7.3.0

## Release Highlights

- [#1361](https://github.com/oauth2-proxy/oauth2-proxy/pull/1541) PKCE Code Challenge Support - RFC-7636 (@braunsonm)
  - At this time the `--code-challenge-method` flag can be used to enable it with the method of your choice.
- Parital support for OAuth2 Authorization Server Metadata for detecting code challenge methods (@braunsonm)
  - A warning will be displayed when your provider advertises support for PKCE but you have not enabled it.
- Support for the ARMv8 and ppc64le architectures
- Configurable upstream request timeouts

## Important Notes

- [oauth2-proxy](https://quay.io/repository/oauth2-proxy/oauth2-proxy?tab=tags&tag=latest) separate image tags for each architecture is deprecated. Instead, images are cross compiled and pushed as the same tag for every platform.
If you are using an architecture specific tag (ex: v7.2.1-arm64) you should move to the generic tag instead (ex: v7.2.1 )
- [#1478](https://github.com/oauth2-proxy/oauth2-proxy/pull/1478) Changes the UID and GID of the runtime user to `65532`.
  Which also is known as `nonroot` user in [distroless images](https://github.com/GoogleContainerTools/distroless).
- This release includes fixes for a number of CVEs, we recomend to upgrade as soon as possible.

## Breaking Changes

- [#1666](https://github.com/oauth2-proxy/oauth2-proxy/issues/1666) Azure provider breaks after upgrading to this version. Please see the issue for more details.

## Changes since v7.2.1

- [#1662](https://github.com/oauth2-proxy/oauth2-proxy/pull/1662) Discover signature algorithms from OIDC provider (@JoelSpeed)
- [#1651](https://github.com/oauth2-proxy/oauth2-proxy/pull/1651) Updated go-lang's text, crypto and prometheus dependencies to fix reported security vulnerabilities. (@rkkris75)
- [#1595](https://github.com/oauth2-proxy/oauth2-proxy/pull/1595) Add optional `allowed_emails` query parameter to the `auth_request`. (@zv0n)
- [#1478](https://github.com/oauth2-proxy/oauth2-proxy/pull/1478) Parameterise the runtime image (@omBratteng)
- [#1583](https://github.com/oauth2-proxy/oauth2-proxy/pull/1583) Add groups to session too when creating session from bearer token (@adriananeci)
- [#1418](https://github.com/oauth2-proxy/oauth2-proxy/pull/1418) Support for passing arbitrary query parameters through from `/oauth2/start` to the identity provider's login URL. Configuration settings control which parameters are passed by default and precisely which values can be overridden per-request (@ianroberts)
- [#1559](https://github.com/oauth2-proxy/oauth2-proxy/pull/1559) Introduce ProviderVerifier to clean up OIDC discovery code (@JoelSpeed)
- [#1561](https://github.com/oauth2-proxy/oauth2-proxy/pull/1561) Add ppc64le support (@mgiessing)
- [#1563](https://github.com/oauth2-proxy/oauth2-proxy/pull/1563) Ensure claim extractor does not attempt profile call when URL is empty (@JoelSpeed)
- [#1560](https://github.com/oauth2-proxy/oauth2-proxy/pull/1560) Fix provider data initialisation (@JoelSpeed)
- [#1555](https://github.com/oauth2-proxy/oauth2-proxy/pull/1555) Refactor provider configuration into providers package (@JoelSpeed)
- [#1394](https://github.com/oauth2-proxy/oauth2-proxy/pull/1394) Add generic claim extractor to get claims from ID Tokens (@JoelSpeed)
- [#1468](https://github.com/oauth2-proxy/oauth2-proxy/pull/1468) Implement session locking with session state lock (@JoelSpeed, @Bibob7)
- [#1489](https://github.com/oauth2-proxy/oauth2-proxy/pull/1489) Fix Docker Buildx push to include build version (@JoelSpeed)
- [#1477](https://github.com/oauth2-proxy/oauth2-proxy/pull/1477) Remove provider documentation for `Microsoft Azure AD` (@omBratteng)
- [#1204](https://github.com/oauth2-proxy/oauth2-proxy/pull/1204) Added configuration for audience claim (`--oidc-extra-audience`) and ability to specify extra audiences (`--oidc-extra-audience`) allowed passing audience verification. This enables support for AWS Cognito and other issuers that have custom audience claims. Also, this adds the ability to allow multiple audiences. (@kschu91)
- [#1509](https://github.com/oauth2-proxy/oauth2-proxy/pull/1509) Update LoginGovProvider ValidateSession to pass access_token in Header (@pksheldon4)
- [#1474](https://github.com/oauth2-proxy/oauth2-proxy/pull/1474) Support configuration of minimal acceptable TLS version (@polarctos)
- [#1545](https://github.com/oauth2-proxy/oauth2-proxy/pull/1545) Fix issue with query string allowed group panic on skip methods (@andytson)
- [#1286](https://github.com/oauth2-proxy/oauth2-proxy/pull/1286) Add the `allowed_email_domains` and the `allowed_groups` on the `auth_request` + support standard wildcard char for validation with sub-domain and email-domain. (@w3st3ry @armandpicard)
- [#1361](https://github.com/oauth2-proxy/oauth2-proxy/pull/1541) PKCE Code Challenge Support - RFC-7636 (@braunsonm)
- [#1594](https://github.com/oauth2-proxy/oauth2-proxy/pull/1594) Release ARMv8 docker images (@braunsonm)
- [#1649](https://github.com/oauth2-proxy/oauth2-proxy/pull/1649) Return a 400 instead of a 500 when a request contains an invalid redirect target (@niksko)
- [#1638](https://github.com/oauth2-proxy/oauth2-proxy/pull/1638) Implement configurable upstream timeout (@jacksgt)
- [#1650](https://github.com/oauth2-proxy/oauth2-proxy/pull/1650) Fixed 500 when checking if user has repo (@adamsong)
- [#1635](https://github.com/oauth2-proxy/oauth2-proxy/pull/1635) Added description and unit tests for ipv6 address (@t-katsumura)
- [#1502](https://github.com/oauth2-proxy/oauth2-proxy/pull/1502) Unbreak oauth2-proxy for keycloak provider after 2c668a (@ckwalsh)

# V7.2.1

## Release Highlights

This release contains a number of bug and security fixes, but has no feature additions.

## Important Notes

N/A

## Breaking Changes

N/A

## Changes since v7.2.0

- [#1247](https://github.com/oauth2-proxy/oauth2-proxy/pull/1247) Use `upn` claim consistently in ADFSProvider (@NickMeves)
- [#1447](https://github.com/oauth2-proxy/oauth2-proxy/pull/1447) Fix docker build/push issues found during last release (@JoelSpeed)
- [#1433](https://github.com/oauth2-proxy/oauth2-proxy/pull/1433) Let authentication fail when session validation fails (@stippi2)
- [#1445](https://github.com/oauth2-proxy/oauth2-proxy/pull/1445) Fix docker container multi arch build issue by passing GOARCH details to make build (@jkandasa)
- [#1444](https://github.com/oauth2-proxy/oauth2-proxy/pull/1444) Update LinkedIn provider validate URL (@jkandasa)
- [#1471](https://github.com/oauth2-proxy/oauth2-proxy/pull/1471) Update alpine to 3.15 (@AlexanderBabel)
- [#1479](https://github.com/oauth2-proxy/oauth2-proxy/pull/1479) Update to Go 1.17 (@polarctos)

# V7.2.0

## Release Highlights

- LinkedIn provider updated to support the new v2 API
- Introduce `--force-json-errors` to allow OAuth2 Proxy to protect JSON APIs and disable authentication redirection
- Add URL rewrite capabilities to the upstream proxy
- New ADFS provider integration
- New Keycloak OIDC provider integration
- Introduced Multiarch Docker images on the standard image tags

## Important Notes

- [#1086](https://github.com/oauth2-proxy/oauth2-proxy/pull/1086) The extra validation to protect invalid session
  deserialization from v6.0.0 (only) has been removed to improve performance. If you are on v6.0.0, either upgrade
  to a version before this first and allow legacy sessions to expire gracefully or change your `cookie-secret`
  value and force all sessions to reauthenticate.
- [#1210](https://github.com/oauth2-proxy/oauth2-proxy/pull/1210) A new `keycloak-oidc` provider has been added with support for role based authentication. The existing keycloak auth provider will eventually be deprecated and removed. Please switch to the new provider `keycloak-oidc`.

## Breaking Changes

- [#1239](https://github.com/oauth2-proxy/oauth2-proxy/pull/1239) GitLab groups sent in the `X-Forwarded-Groups` header
  to the upstream server will no longer be prefixed with `group:`

## Changes since v7.1.3

- [#1391](https://github.com/oauth2-proxy/oauth2-proxy/pull/1391) Improve build times by sharing cache and allowing platform selection (@JoelSpeed)
- [#1404](https://github.com/oauth2-proxy/oauth2-proxy/pull/1404) Improve error message when no cookie is found (@JoelSpeed)
- [#1315](https://github.com/oauth2-proxy/oauth2-proxy/pull/1315) linkedin: Update provider to v2 (@wuurrd)
- [#1348](https://github.com/oauth2-proxy/oauth2-proxy/pull/1348) Using the native httputil proxy code for websockets rather than yhat/wsutil to properly handle HTTP-level failures (@thetrime)
- [#1379](https://github.com/oauth2-proxy/oauth2-proxy/pull/1379) Fix the manual sign in with --htpasswd-user-group switch (@janrotter)
- [#1375](https://github.com/oauth2-proxy/oauth2-proxy/pull/1375) Added `--force-json-errors` flag (@bancek)
- [#1337](https://github.com/oauth2-proxy/oauth2-proxy/pull/1337) Changing user field type to text when using htpasswd (@pburgisser)
- [#1239](https://github.com/oauth2-proxy/oauth2-proxy/pull/1239) Base GitLab provider implementation on OIDCProvider (@NickMeves)
- [#1276](https://github.com/oauth2-proxy/oauth2-proxy/pull/1276) Update crypto and switched to new github.com/golang-jwt/jwt (@JVecsei)
- [#1264](https://github.com/oauth2-proxy/oauth2-proxy/pull/1264) Update go-oidc to v3 (@NickMeves)
- [#1233](https://github.com/oauth2-proxy/oauth2-proxy/pull/1233) Extend email-domain validation with sub-domain capability (@morarucostel)
- [#1060](https://github.com/oauth2-proxy/oauth2-proxy/pull/1060) Implement RewriteTarget to allow requests to be rewritten before proxying to upstream servers (@JoelSpeed)
- [#1086](https://github.com/oauth2-proxy/oauth2-proxy/pull/1086) Refresh sessions before token expiration if configured (@NickMeves)
- [#1226](https://github.com/oauth2-proxy/oauth2-proxy/pull/1226) Move app redirection logic to its own package (@JoelSpeed)
- [#1128](https://github.com/oauth2-proxy/oauth2-proxy/pull/1128) Use gorilla mux for OAuth Proxy routing (@JoelSpeed)
- [#1238](https://github.com/oauth2-proxy/oauth2-proxy/pull/1238) Added ADFS provider (@samirachoadi)
- [#1227](https://github.com/oauth2-proxy/oauth2-proxy/pull/1227) Fix Refresh Session not working for multiple cookies (@rishi1111)
- [#1063](https://github.com/oauth2-proxy/oauth2-proxy/pull/1063) Add Redis lock feature to lock persistent sessions (@Bibob7)
- [#1108](https://github.com/oauth2-proxy/oauth2-proxy/pull/1108) Add alternative ways to generate cookie secrets to docs (@JoelSpeed)
- [#1142](https://github.com/oauth2-proxy/oauth2-proxy/pull/1142) Add pagewriter to upstream proxy (@JoelSpeed)
- [#1181](https://github.com/oauth2-proxy/oauth2-proxy/pull/1181) Fix incorrect `cfg` name in show-debug-on-error flag (@iTaybb)
- [#1207](https://github.com/oauth2-proxy/oauth2-proxy/pull/1207) Fix URI fragment handling on sign-in page, regression introduced in 7.1.0 (@tarvip)
- [#1210](https://github.com/oauth2-proxy/oauth2-proxy/pull/1210) New Keycloak OIDC Provider (@pb82)
- [#1244](https://github.com/oauth2-proxy/oauth2-proxy/pull/1244) Update Alpine image version to 3.14 (@ahovgaard)
- [#1317](https://github.com/oauth2-proxy/oauth2-proxy/pull/1317) Fix incorrect `</form>` tag on the sing_in page when *not* using a custom template (@jord1e)
- [#1330](https://github.com/oauth2-proxy/oauth2-proxy/pull/1330) Allow specifying URL as input for custom sign in logo (@MaikuMori)
- [#1357](https://github.com/oauth2-proxy/oauth2-proxy/pull/1357) Fix unsafe access to session variable (@harzallah)
- [#997](https://github.com/oauth2-proxy/oauth2-proxy/pull/997) Allow passing the raw url path when proxying upstream requests - e.g. /%2F/ (@FStelzer)
- [#1147](https://github.com/oauth2-proxy/oauth2-proxy/pull/1147) Multiarch support for docker image (@goshlanguage)
- [#1296](https://github.com/oauth2-proxy/oauth2-proxy/pull/1296) Fixed `panic` when connecting to Redis with TLS (@mstrzele)
- [#1403](https://github.com/oauth2-proxy/oauth2-proxy/pull/1403) Improve TLS handling for Redis to support non-standalone mode with TLS (@wadahiro)

# V7.1.3

## Release Highlights

- Fixed typos in the metrics server TLS config names

## Important Notes

- [#967](https://github.com/oauth2-proxy/oauth2-proxy/pull/967) `--insecure-oidc-skip-nonce` is currently `true` by default in case
  any existing OIDC Identity Providers don't support it. The default will switch to `false` in a future version.

## Breaking Changes

## Changes since v7.1.2

- [#1168](https://github.com/oauth2-proxy/oauth2-proxy/pull/1168) Fix incorrect `cfg` name in Metrics TLS flags (@NickMeves)
- [#967](https://github.com/oauth2-proxy/oauth2-proxy/pull/967) Set & verify a nonce with OIDC providers (@NickMeves)
- [#1136](https://github.com/oauth2-proxy/oauth2-proxy/pull/1136) Add clock package for better time mocking in tests (@NickMeves)
- [#947](https://github.com/oauth2-proxy/oauth2-proxy/pull/947) Multiple provider ingestion and validation in alpha options (first stage: [#926](https://github.com/oauth2-proxy/oauth2-proxy/issues/926)) (@yanasega)

# V7.1.2

## Release Highlights

- Metrics bind address initialisation was broken in config files

## Important Notes

N/A

## Breaking Changes

N/A

## Changes since v7.1.1

- [#1129](https://github.com/oauth2-proxy/oauth2-proxy/pull/1129) Rewrite OpenRedirect tests in ginkgo (@JoelSpeed)
- [#1127](https://github.com/oauth2-proxy/oauth2-proxy/pull/1127) Remove unused fields from OAuthProxy (@JoelSpeed)
- [#1141](https://github.com/oauth2-proxy/oauth2-proxy/pull/1141) Fix metrics server bind address initialization (@oliver006)

# V7.1.1

## Release Highlights

- The metrics server could not be started in v7.1.0, this is now fixed.

## Important Notes

N/A

## Breaking Changes

N/A

## Changes since v7.1.0

- [#1133](https://github.com/oauth2-proxy/oauth2-proxy/pull/1133) Metrics server should be constructed with secure bind address for TLS (@JoelSpeed)

# V7.1.0

## Release Highlights

- New improved design for sign in and error pages based on bulma framework
- Refactored templates loading
  - `robots.txt`, `sign_in.html` and `error.html` can now be provided individually in `--custom-templates-dir`
  - If any of the above are not provided, defaults are used
  - Defaults templates be found in [pkg/app/pagewriter](https://github.com/oauth2-proxy/oauth2-proxy/tree/v7.1.0/pkg/app/pagewriter)
- Introduction of basic prometheus metrics
- Introduction of Traefik based local testing/example environment
- Support for request IDs to allow request co-ordination of log lines

## Important Notes

- [GHSA-652x-m2gr-hppm](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-652x-m2gr-hppm) GitLab group authorization stopped working in v7.0.0, the functionality has now been restored, please see the linked advisory for details
- [#1103](https://github.com/oauth2-proxy/oauth2-proxy/pull/1103) Upstream request signatures via `--signature-key` is
  deprecated. Support will be removed completely in v8.0.0.
- [1087](https://github.com/oauth2-proxy/oauth2-proxy/pull/1087) The default logging templates have been updated to include {{.RequestID}}
- [#1117](https://github.com/oauth2-proxy/oauth2-proxy/pull/1117) The `--gcp-healthchecks` option is now deprecated. It will be removed in a future release.
  - To migrate, you can change your application health checks for OAuth2 Proxy to point to
    the `--ping-path` value.
  - You can also migrate the user agent based health check using the `--ping-user-agent` option. Set it to `GoogleHC/1.0` to allow health checks on the path `/` from the Google health checker.

## Breaking Changes

N/A

## Changes since v7.0.1

- [GHSA-652x-m2gr-hppm](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-652x-m2gr-hppm) `--gitlab-group` GitLab Group Authorization config flag stopped working in v7.0.0 (@NickMeves, @papey)
- [#1113](https://github.com/oauth2-proxy/oauth2-proxy/pull/1113) Panic with GitLab project repository auth (@piersharding)
- [#1116](https://github.com/oauth2-proxy/oauth2-proxy/pull/1116) Reinstate preferEmailToUser behaviour for basic auth sessions (@JoelSpeed)
- [#1115](https://github.com/oauth2-proxy/oauth2-proxy/pull/1115) Fix upstream proxy appending ? to requests (@JoelSpeed)
- [#1117](https://github.com/oauth2-proxy/oauth2-proxy/pull/1117) Deprecate GCP HealthCheck option (@JoelSpeed)
- [#1104](https://github.com/oauth2-proxy/oauth2-proxy/pull/1104) Allow custom robots text pages (@JoelSpeed)
- [#1045](https://github.com/oauth2-proxy/oauth2-proxy/pull/1045) Ensure redirect URI always has a scheme (@JoelSpeed)
- [#1103](https://github.com/oauth2-proxy/oauth2-proxy/pull/1103) Deprecate upstream request signatures (@NickMeves)
- [#1087](https://github.com/oauth2-proxy/oauth2-proxy/pull/1087) Support Request ID in logging (@NickMeves)
- [#914](https://github.com/oauth2-proxy/oauth2-proxy/pull/914) Extract email from id_token for azure provider when oidc is configured (@weinong)
- [#1047](https://github.com/oauth2-proxy/oauth2-proxy/pull/1047) Refactor HTTP Server and add ServerGroup to handle graceful shutdown of multiple servers (@JoelSpeed)
- [#1070](https://github.com/oauth2-proxy/oauth2-proxy/pull/1070) Refactor logging middleware to middleware package (@NickMeves)
- [#1064](https://github.com/oauth2-proxy/oauth2-proxy/pull/1064) Add support for setting groups on session when using basic auth (@stefansedich)
- [#1056](https://github.com/oauth2-proxy/oauth2-proxy/pull/1056) Add option for custom logos on the sign in page (@JoelSpeed)
- [#1054](https://github.com/oauth2-proxy/oauth2-proxy/pull/1054) Update to Go 1.16 (@JoelSpeed)
- [#1052](https://github.com/oauth2-proxy/oauth2-proxy/pull/1052) Update golangci-lint to latest version (v1.36.0) (@JoelSpeed)
- [#1043](https://github.com/oauth2-proxy/oauth2-proxy/pull/1043) Refactor Sign In Page rendering and capture all page rendering code in pagewriter package (@JoelSpeed)
- [#1029](https://github.com/oauth2-proxy/oauth2-proxy/pull/1029) Refactor error page rendering and allow debug messages on error (@JoelSpeed)
- [#1028](https://github.com/oauth2-proxy/oauth2-proxy/pull/1028) Refactor templates, update theme and provide styled error pages (@JoelSpeed)
- [#1039](https://github.com/oauth2-proxy/oauth2-proxy/pull/1039) Ensure errors in tests are logged to the GinkgoWriter (@JoelSpeed)
- [#980](https://github.com/oauth2-proxy/oauth2-proxy/pull/980) Add Prometheus metrics endpoint (@neuralsandwich)
- [#1023](https://github.com/oauth2-proxy/oauth2-proxy/pull/1023) Update docs on Traefik ForwardAuth support without the use of Traefik 'errors' middleware (@pcneo83)
- [#1091](https://github.com/oauth2-proxy/oauth2-proxy/pull/1091) Add an example with Traefik (configuration without Traefik 'errors' middleware) (@fcollonval)

# V7.0.1

## Release Highlights

- Fixed a bug that meant that flag ordering mattered
- Fixed a bug where response headers for groups were not being flattened

## Important Notes

N/A

## Breaking Changes

N/A

## Changes since v7.0.0

- [#1020](https://github.com/oauth2-proxy/oauth2-proxy/pull/1020) Flatten array-based response headers (@NickMeves)
- [#1026](https://github.com/oauth2-proxy/oauth2-proxy/pull/1026) Ensure config flags get parsed correctly when other flags precede them (@JoelSpeed)

# V7.0.0

## Release Highlights

- Major internal improvements to provider interfaces
- Added group authorization support
- Improved support for external auth for Traefik
- Introduced alpha configuration format to allow users to trial new configuration format and alpha features
- GitLab provider now supports restricting to members of a project
- Keycloak provider now supports restricting users to members of a set of groups
- (Alpha) Flexible header configuration allowing user defined mapping of session claims to header values


## Important Notes

- [GHSA-4mf2-f3wh-gvf2](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-4mf2-f3wh-gvf2) The whitelist domain feature has been updated to fix a vulnerability that was identified, please see the linked advisory for details
- [#964](https://github.com/oauth2-proxy/oauth2-proxy/pull/964) Redirect URL generation will attempt secondary strategies
  in the priority chain if any fail the `IsValidRedirect` security check. Previously any failures fell back to `/`.
- [#953](https://github.com/oauth2-proxy/oauth2-proxy/pull/953) Keycloak will now use `--profile-url` if set for the userinfo endpoint
  instead of `--validate-url`. `--validate-url` will still work for backwards compatibility.
- [#957](https://github.com/oauth2-proxy/oauth2-proxy/pull/957) To use X-Forwarded-{Proto,Host,Uri} on redirect detection, `--reverse-proxy` must be `true`.
- [#936](https://github.com/oauth2-proxy/oauth2-proxy/pull/936) `--user-id-claim` option is deprecated and replaced by `--oidc-email-claim`
- [#630](https://github.com/oauth2-proxy/oauth2-proxy/pull/630) Gitlab projects needs a Gitlab application with the extra `read_api` enabled
- [#849](https://github.com/oauth2-proxy/oauth2-proxy/pull/849) `/oauth2/auth` `allowed_groups` querystring parameter can be paired with the `allowed-groups` configuration option.
  - The `allowed_groups` querystring parameter can specify multiple comma delimited groups.
  - In this scenario, the user must have a group (from their multiple groups) present in both lists to not get a 401 or 403 response code.
  - Example:
    - OAuth2-Proxy globally sets the `allowed_groups` as `engineering`.
    - An application using Kubernetes ingress uses the `/oauth2/auth` endpoint with `allowed_groups` querystring set to `backend`.
    - A user must have a session with the groups `["engineering", "backend"]` to pass authorization.
    - Another user with the groups `["engineering", "frontend"]` would fail the querystring authorization portion.
- [#905](https://github.com/oauth2-proxy/oauth2-proxy/pull/905) Existing sessions from v6.0.0 or earlier are no longer valid. They will trigger a reauthentication.
- [#826](https://github.com/oauth2-proxy/oauth2-proxy/pull/826) `skip-auth-strip-headers` now applies to all requests, not just those where authentication would be skipped.
- [#797](https://github.com/oauth2-proxy/oauth2-proxy/pull/797) The behavior of the Google provider Groups restriction changes with this
  - Either `--google-group` or the new `--allowed-group` will work for Google now (`--google-group` will be used if both are set)
  - Group membership lists will be passed to the backend with the `X-Forwarded-Groups` header
  - If you change the list of allowed groups, existing sessions that now don't have a valid group will be logged out immediately.
    - Previously, group membership was only checked on session creation and refresh.
- [#789](https://github.com/oauth2-proxy/oauth2-proxy/pull/789) `--skip-auth-route` is (almost) backwards compatible with `--skip-auth-regex`
  - We are marking `--skip-auth-regex` as DEPRECATED and will remove it in the next major version.
  - If your regex contains an `=` and you want it for all methods, you will need to add a leading `=` (this is the area where `--skip-auth-regex` doesn't port perfectly)
- [#575](https://github.com/oauth2-proxy/oauth2-proxy/pull/575) Sessions from v5.1.1 or earlier will no longer validate since they were not signed with SHA1.
  - Sessions from v6.0.0 or later had a graceful conversion to SHA256 that resulted in no reauthentication
  - Upgrading from v5.1.1 or earlier will result in a reauthentication
- [#616](https://github.com/oauth2-proxy/oauth2-proxy/pull/616) Ensure you have configured oauth2-proxy to use the `groups` scope.
  - The user may be logged out initially as they may not currently have the `groups` claim however after going back through login process wil be authenticated.
- [#839](https://github.com/oauth2-proxy/oauth2-proxy/pull/839) Enables complex data structures for group claim entries, which are output as Json by default.

## Breaking Changes

- [#964](https://github.com/oauth2-proxy/oauth2-proxy/pull/964) `--reverse-proxy` must be true to trust `X-Forwarded-*` headers as canonical.
  These are used throughout the application in redirect URLs, cookie domains and host logging logic. These are the headers:
  - `X-Forwarded-Proto` instead of `req.URL.Scheme`
  - `X-Forwarded-Host` instead of `req.Host`
  - `X-Forwarded-Uri` instead of `req.URL.RequestURI()`
- [#953](https://github.com/oauth2-proxy/oauth2-proxy/pull/953) In config files & envvar configs, `keycloak_group` is now the plural `keycloak_groups`.
  Flag configs are still `--keycloak-group` but it can be passed multiple times.
- [#911](https://github.com/oauth2-proxy/oauth2-proxy/pull/911) Specifying a non-existent provider will cause OAuth2-Proxy to fail on startup instead of defaulting to "google".
- [#797](https://github.com/oauth2-proxy/oauth2-proxy/pull/797) Security changes to Google provider group authorization flow
  - If you change the list of allowed groups, existing sessions that now don't have a valid group will be logged out immediately.
    - Previously, group membership was only checked on session creation and refresh.
- [#722](https://github.com/oauth2-proxy/oauth2-proxy/pull/722) When a Redis session store is configured, OAuth2-Proxy will fail to start up unless connection and health checks to Redis pass
- [#800](https://github.com/oauth2-proxy/oauth2-proxy/pull/800) Fix import path for v7. The import path has changed to support the go get installation.
  - You can now `go get github.com/oauth2-proxy/oauth2-proxy/v7` to get the latest `v7` version of OAuth2 Proxy
  - Import paths for package are now under `v7`, eg `github.com/oauth2-proxy/oauth2-proxy/v7/pkg/<module>`
- [#753](https://github.com/oauth2-proxy/oauth2-proxy/pull/753) A bug in the Azure provider prevented it from properly passing the configured protected `--resource`
  via the login url. If this option was used in the past, behavior will change with this release as it will
  affect the tokens returned by Azure. In the past, the tokens were always for `https://graph.microsoft.com` (the default)
  and will now be for the configured resource (if it exists, otherwise it will run into errors)
- [#754](https://github.com/oauth2-proxy/oauth2-proxy/pull/754) The Azure provider now has token refresh functionality implemented. This means that there won't
  be any redirects in the browser anymore when tokens expire, but instead a token refresh is initiated
  in the background, which leads to new tokens being returned in the cookies.
  - Please note that `--cookie-refresh` must be 0 (the default) or equal to the token lifespan configured in Azure AD to make
    Azure token refresh reliable. Setting this value to 0 means that it relies on the provider implementation
    to decide if a refresh is required.

## Changes since v6.1.1

- [GHSA-4mf2-f3wh-gvf2](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-4mf2-f3wh-gvf2) Subdomain checking of whitelisted domains could allow unintended redirects (@NickMeves)
- [#1002](https://github.com/oauth2-proxy/oauth2-proxy/pull/1002) Use logger for logging refreshed session in azure and gitlab provider (@Bibob7)
- [#799](https://github.com/oauth2-proxy/oauth2-proxy/pull/799) Use comma separated multiple values for header (@lilida)
- [#903](https://github.com/oauth2-proxy/oauth2-proxy/pull/903) Add docs and generated reference for Alpha configuration (@JoelSpeed)
- [#995](https://github.com/oauth2-proxy/oauth2-proxy/pull/995) Add Security Policy (@JoelSpeed)
- [#964](https://github.com/oauth2-proxy/oauth2-proxy/pull/964) Require `--reverse-proxy` true to trust `X-Forwareded-*` type headers (@NickMeves)
- [#970](https://github.com/oauth2-proxy/oauth2-proxy/pull/970) Fix joined cookie name for those containing underline in the suffix (@peppered)
- [#953](https://github.com/oauth2-proxy/oauth2-proxy/pull/953) Migrate Keycloak to EnrichSession & support multiple groups for authorization (@NickMeves)
- [#957](https://github.com/oauth2-proxy/oauth2-proxy/pull/957) Use X-Forwarded-{Proto,Host,Uri} on redirect as last resort (@linuxgemini)
- [#630](https://github.com/oauth2-proxy/oauth2-proxy/pull/630) Add support for Gitlab project based authentication (@factorysh)
- [#907](https://github.com/oauth2-proxy/oauth2-proxy/pull/907) Introduce alpha configuration option to enable testing of structured configuration (@JoelSpeed)
- [#938](https://github.com/oauth2-proxy/oauth2-proxy/pull/938) Cleanup missed provider renaming refactor methods (@NickMeves)
- [#816](https://github.com/oauth2-proxy/oauth2-proxy/pull/816) (via [#936](https://github.com/oauth2-proxy/oauth2-proxy/pull/936)) Support non-list group claims (@loafoe)
- [#936](https://github.com/oauth2-proxy/oauth2-proxy/pull/936) Refactor OIDC Provider and support groups from Profile URL (@NickMeves)
- [#869](https://github.com/oauth2-proxy/oauth2-proxy/pull/869) Streamline provider interface method names and signatures (@NickMeves)
- [#849](https://github.com/oauth2-proxy/oauth2-proxy/pull/849) Support group authorization on `oauth2/auth` endpoint via `allowed_groups` querystring (@NickMeves)
- [#925](https://github.com/oauth2-proxy/oauth2-proxy/pull/925) Fix basic auth legacy header conversion (@JoelSpeed)
- [#916](https://github.com/oauth2-proxy/oauth2-proxy/pull/916) Add AlphaOptions struct to prepare for alpha config loading (@JoelSpeed)
- [#923](https://github.com/oauth2-proxy/oauth2-proxy/pull/923) Support TLS 1.3 (@aajisaka)
- [#918](https://github.com/oauth2-proxy/oauth2-proxy/pull/918) Fix log header output (@JoelSpeed)
- [#911](https://github.com/oauth2-proxy/oauth2-proxy/pull/911) Validate provider type on startup. (@arcivanov)
- [#906](https://github.com/oauth2-proxy/oauth2-proxy/pull/906) Set up v6.1.x versioned documentation as default documentation (@JoelSpeed)
- [#905](https://github.com/oauth2-proxy/oauth2-proxy/pull/905) Remove v5 legacy sessions support (@NickMeves)
- [#904](https://github.com/oauth2-proxy/oauth2-proxy/pull/904) Set `skip-auth-strip-headers` to `true` by default (@NickMeves)
- [#826](https://github.com/oauth2-proxy/oauth2-proxy/pull/826) Integrate new header injectors into project (@JoelSpeed)
- [#797](https://github.com/oauth2-proxy/oauth2-proxy/pull/797) Create universal Authorization behavior across providers (@NickMeves)
- [#898](https://github.com/oauth2-proxy/oauth2-proxy/pull/898) Migrate documentation to Docusaurus (@JoelSpeed)
- [#754](https://github.com/oauth2-proxy/oauth2-proxy/pull/754) Azure token refresh (@codablock)
- [#850](https://github.com/oauth2-proxy/oauth2-proxy/pull/850) Increase session fields in `/oauth2/userinfo` endpoint (@NickMeves)
- [#825](https://github.com/oauth2-proxy/oauth2-proxy/pull/825) Fix code coverage reporting on GitHub actions(@JoelSpeed)
- [#796](https://github.com/oauth2-proxy/oauth2-proxy/pull/796) Deprecate GetUserName & GetEmailAdress for EnrichSessionState (@NickMeves)
- [#705](https://github.com/oauth2-proxy/oauth2-proxy/pull/705) Add generic Header injectors for upstream request and response headers (@JoelSpeed)
- [#753](https://github.com/oauth2-proxy/oauth2-proxy/pull/753) Pass resource parameter in login url (@codablock)
- [#789](https://github.com/oauth2-proxy/oauth2-proxy/pull/789) Add `--skip-auth-route` configuration option for `METHOD=pathRegex` based allowlists (@NickMeves)
- [#575](https://github.com/oauth2-proxy/oauth2-proxy/pull/575) Stop accepting legacy SHA1 signed cookies (@NickMeves)
- [#722](https://github.com/oauth2-proxy/oauth2-proxy/pull/722) Validate Redis configuration options at startup (@NickMeves)
- [#791](https://github.com/oauth2-proxy/oauth2-proxy/pull/791) Remove GetPreferredUsername method from provider interface (@NickMeves)
- [#764](https://github.com/oauth2-proxy/oauth2-proxy/pull/764) Document bcrypt encryption for htpasswd (and hide SHA) (@lentzi90)
- [#778](https://github.com/oauth2-proxy/oauth2-proxy/pull/778) Use display-htpasswd-form flag
- [#616](https://github.com/oauth2-proxy/oauth2-proxy/pull/616) Add support to ensure user belongs in required groups when using the OIDC provider (@stefansedich)
- [#800](https://github.com/oauth2-proxy/oauth2-proxy/pull/800) Fix import path for v7 (@johejo)
- [#783](https://github.com/oauth2-proxy/oauth2-proxy/pull/783) Update Go to 1.15 (@johejo)
- [#813](https://github.com/oauth2-proxy/oauth2-proxy/pull/813) Fix build (@thiagocaiubi)
- [#801](https://github.com/oauth2-proxy/oauth2-proxy/pull/801) Update go-redis/redis to v8 (@johejo)
- [#750](https://github.com/oauth2-proxy/oauth2-proxy/pull/750) ci: Migrate to Github Actions (@shinebayar-g)
- [#829](https://github.com/oauth2-proxy/oauth2-proxy/pull/820) Rename test directory to testdata (@johejo)
- [#819](https://github.com/oauth2-proxy/oauth2-proxy/pull/819) Improve CI (@johejo)
- [#989](https://github.com/oauth2-proxy/oauth2-proxy/pull/989) Adapt isAjax to support mimetype lists (@rassie)
- [#1013](https://github.com/oauth2-proxy/oauth2-proxy/pull/1013) Update alpine version to 3.13 (@nishanth-pinnapareddy)

# v6.1.1

## Release Highlights

- Fixed a bug which prevented static upstreams from being used
- Fixed a bug which prevented file based upstreams from being used
- Ensure that X-Forwarded-Host is respected consistently

## Important Notes

N/A

## Breaking

N/A

## Changes since v6.1.0

- [#729](https://github.com/oauth2-proxy/oauth2-proxy/pull/729) Use X-Forwarded-Host consistently when set (@NickMeves)
- [#746](https://github.com/oauth2-proxy/oauth2-proxy/pull/746) Fix conversion of static responses in upstreams (@JoelSpeed)

# v6.1.0

## Release Highlights

- Redis session stores now support authenticated connections
- Error logging can now be separated from info logging by directing error logs to stderr
- Added --session-cookie-minimal flag which helps prevent large session cookies
- Improvements to force-https behaviour
- Allow requests to skip authentication based on their source IP

## Important Notes

- [#632](https://github.com/oauth2-proxy/oauth2-proxy/pull/632) There is backwards compatibility to sessions from v5
  - Any unencrypted sessions from before v5 that only contained a Username & Email will trigger a reauthentication

## Breaking Changes

## Changes since v6.0.0

- [#742](https://github.com/oauth2-proxy/oauth2-proxy/pull/742) Only log no cookie match if cookie domains specified (@JoelSpeed)
- [#562](https://github.com/oauth2-proxy/oauth2-proxy/pull/562) Create generic Authorization Header constructor (@JoelSpeed)
- [#715](https://github.com/oauth2-proxy/oauth2-proxy/pull/715) Ensure session times are not nil before printing them (@JoelSpeed)
- [#714](https://github.com/oauth2-proxy/oauth2-proxy/pull/714) Support passwords with Redis session stores (@NickMeves)
- [#719](https://github.com/oauth2-proxy/oauth2-proxy/pull/719) Add Gosec fixes to areas that are intermittently flagged on PRs (@NickMeves)
- [#718](https://github.com/oauth2-proxy/oauth2-proxy/pull/718) Allow Logging to stdout with separate Error Log Channel
- [#690](https://github.com/oauth2-proxy/oauth2-proxy/pull/690) Address GoSec security findings & remediate (@NickMeves)
- [#689](https://github.com/oauth2-proxy/oauth2-proxy/pull/689) Fix finicky logging_handler_test from time drift (@NickMeves)
- [#700](https://github.com/oauth2-proxy/oauth2-proxy/pull/700) Allow OIDC Bearer auth IDTokens to have empty email claim & profile URL (@NickMeves)
- [#699](https://github.com/oauth2-proxy/oauth2-proxy/pull/699) Align persistence ginkgo tests with conventions (@NickMeves)
- [#696](https://github.com/oauth2-proxy/oauth2-proxy/pull/696) Preserve query when building redirect
- [#561](https://github.com/oauth2-proxy/oauth2-proxy/pull/561) Refactor provider URLs to package level vars (@JoelSpeed)
- [#682](https://github.com/oauth2-proxy/oauth2-proxy/pull/682) Refactor persistent session store session ticket management (@NickMeves)
- [#688](https://github.com/oauth2-proxy/oauth2-proxy/pull/688) Refactor session loading to make use of middleware pattern (@JoelSpeed)
- [#593](https://github.com/oauth2-proxy/oauth2-proxy/pull/593) Integrate upstream package with OAuth2 Proxy (@JoelSpeed)
- [#687](https://github.com/oauth2-proxy/oauth2-proxy/pull/687) Refactor HTPasswd Validator (@JoelSpeed)
- [#624](https://github.com/oauth2-proxy/oauth2-proxy/pull/624) Allow stripping authentication headers from whitelisted requests with `--skip-auth-strip-headers` (@NickMeves)
- [#673](https://github.com/oauth2-proxy/oauth2-proxy/pull/673) Add --session-cookie-minimal option to create session cookies with no tokens (@NickMeves)
- [#632](https://github.com/oauth2-proxy/oauth2-proxy/pull/632) Reduce session size by encoding with MessagePack and using LZ4 compression (@NickMeves)
- [#675](https://github.com/oauth2-proxy/oauth2-proxy/pull/675) Fix required ruby version and deprecated option for building docs (@mkontani)
- [#669](https://github.com/oauth2-proxy/oauth2-proxy/pull/669) Reduce docker context to improve build times (@JoelSpeed)
- [#668](https://github.com/oauth2-proxy/oauth2-proxy/pull/668) Use req.Host in --force-https when req.URL.Host is empty (@zucaritask)
- [#660](https://github.com/oauth2-proxy/oauth2-proxy/pull/660) Use builder pattern to simplify requests to external endpoints (@JoelSpeed)
- [#591](https://github.com/oauth2-proxy/oauth2-proxy/pull/591) Introduce upstream package with new reverse proxy implementation (@JoelSpeed)
- [#576](https://github.com/oauth2-proxy/oauth2-proxy/pull/576) Separate Cookie validation out of main options validation (@JoelSpeed)
- [#656](https://github.com/oauth2-proxy/oauth2-proxy/pull/656) Split long session cookies more precisely (@NickMeves)
- [#619](https://github.com/oauth2-proxy/oauth2-proxy/pull/619) Improve Redirect to HTTPs behaviour (@JoelSpeed)
- [#654](https://github.com/oauth2-proxy/oauth2-proxy/pull/654) Close client connections after each redis test (@JoelSpeed)
- [#542](https://github.com/oauth2-proxy/oauth2-proxy/pull/542) Move SessionStore tests to independent package (@JoelSpeed)
- [#577](https://github.com/oauth2-proxy/oauth2-proxy/pull/577) Move Cipher and Session Store initialisation out of Validation (@JoelSpeed)
- [#635](https://github.com/oauth2-proxy/oauth2-proxy/pull/635) Support specifying alternative provider TLS trust source(s) (@k-wall)
- [#649](https://github.com/oauth2-proxy/oauth2-proxy/pull/650) Resolve an issue where an empty healthcheck URL and ping-user-agent returns the healthcheck response (@jordancrawfordnz)
- [#662](https://github.com/oauth2-proxy/oauth2-proxy/pull/662) Do not add Cache-Control header to response from auth only endpoint (@johejo)
- [#552](https://github.com/oauth2-proxy/oauth2-proxy/pull/522) Implements --trusted-ip option to allow clients behind specified IPs or CIDR ranges to bypass authentication (@Izzette)
- [#733](https://github.com/oauth2-proxy/oauth2-proxy/pull/733) dist.sh: remove go version from asset links (@syscll)

# v6.0.0

## Release Highlights

- Migrated to an independent GitHub organisation
- Added local test environment examples using docker-compose and kind
- Error pages will now be rendered when upstream connections fail
- Non-Existent options in config files will now return errors on startup
- Sessions are now always encrypted, independent of configuration

## Important Notes

- (Security) Fix for [open redirect vulnerability](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-5m6c-jp6f-2vcv).
  - More invalid redirects that lead to open-redirects were reported
  - An extensive test suite has been added to prevent future regressions
- [#453](https://github.com/oauth2-proxy/oauth2-proxy/pull/453) Responses to endpoints with a proxy prefix will now return headers for preventing browser caching.

## Breaking Changes

- [#464](https://github.com/oauth2-proxy/oauth2-proxy/pull/464) Migration from Pusher to independent org may have introduced breaking changes for your environment.
  - See the changes listed below for PR [#464](https://github.com/oauth2-proxy/oauth2-proxy/pull/464) for full details
  - Binaries renamed from `oauth2_proxy` to `oauth2-proxy`
- [#440](https://github.com/oauth2-proxy/oauth2-proxy/pull/440) Switch Azure AD Graph API to Microsoft Graph API
  - The Azure AD Graph API has been [deprecated](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api) and is being replaced by the Microsoft Graph API.
    If your application relies on the access token being passed to it to access the Azure AD Graph API, you should migrate your application to use the Microsoft Graph API.
    Existing behaviour can be retained by setting `-resource=https://graph.windows.net`.
- [#484](https://github.com/oauth2-proxy/oauth2-proxy/pull/484) Configuration loading has been replaced with Viper and PFlag
  - Flags now require a `--` prefix before the option
  - Previously flags allowed either `-` or `--` to prefix the option name
  - Eg `-provider` must now be `--provider`
- [#487](https://github.com/oauth2-proxy/oauth2-proxy/pull/487) Switch flags to StringSlice instead of StringArray
  - Options that take multiple arguments now split strings on commas if present
  - Eg `--foo=a,b,c,d` would result in the values `a`, `b`, `c` and `d` instead of a single `a,b,c,d` value as before
- [#535](https://github.com/oauth2-proxy/oauth2-proxy/pull/535) Drop support for pre v3.1 cookies
  - The encoding for session cookies was changed starting in v3.1.0, support for the previous encoding is now dropped
  - If you are upgrading from a version earlier than this, please upgrade via a version between v3.1.0 and v5.1.1
- [#537](https://github.com/oauth2-proxy/oauth2-proxy/pull/537) Drop Fallback to Email if User not set
  - Previously, when a session was loaded, if the User was not set, it would be replaced by the Email.
    This behaviour was inconsistent as it required the session to be stored and then loaded to function properly.
  - This behaviour has now been removed and the User field will remain empty if it was not set when the session was saved.
  - In some scenarios `X-Forwarded-User` will now be empty. Use `X-Forwarded-Email` instead.
  - In some scenarios, this may break setting Basic Auth on upstream or responses.
    Use `--prefer-email-to-user` to restore falling back to the Email in these cases.
- [#556](https://github.com/oauth2-proxy/oauth2-proxy/pull/556) Remove unintentional auto-padding of secrets that were too short
  - Previously, after cookie-secrets were opportunistically base64 decoded to raw bytes,
    they were padded to have a length divisible by 4.
  - This led to wrong sized secrets being valid AES lengths of 16, 24, or 32 bytes. Or it led to confusing errors
    reporting an invalid length of 20 or 28 when the user input cookie-secret was not that length.
  - Now we will only base64 decode a cookie-secret to raw bytes if it is 16, 24, or 32 bytes long. Otherwise, we will convert
    the direct cookie-secret to bytes without silent padding added.
- [#412](https://github.com/oauth2-proxy/oauth2-proxy/pull/412)/[#559](https://github.com/oauth2-proxy/oauth2-proxy/pull/559) Allow multiple cookie domains to be specified
  - Multiple cookie domains may now be configured. The longest domain that matches will be used.
  - The config options `cookie_domain` is now `cookie_domains`
  - The environment variable `OAUTH2_PROXY_COOKIE_DOMAIN` is now `OAUTH2_PROXY_COOKIE_DOMAINS`
- [#414](https://github.com/oauth2-proxy/oauth2-proxy/pull/414) Always encrypt sessions regardless of config
  - Previously, sessions were encrypted only when certain options were configured.
    This lead to confusion and misconfiguration as it was not obvious when a session should be encrypted.
  - Cookie Secrets must now be 16, 24 or 32 bytes.
  - If you need to change your secret, this will force users to reauthenticate.
- [#548](https://github.com/oauth2-proxy/oauth2-proxy/pull/548) Separate logging options out of main options structure
  - Fixes an inconsistency in the `--exclude-logging-paths` option by renaming it to `--exclude-logging-option`.
  - This flag may now be given multiple times as with other list options
  - This flag also accepts comma separated values
- [#639](https://github.com/oauth2-proxy/oauth2-proxy/pull/639) Change how gitlab-group is parsed on options
  - Previously, the flag gitlab-group used comma seperated values, while the config option used space seperated values.
  - This fixes the config value to use slices internally.
  - The config option `gitlab_group` is now `gitlab_groups`
  - The environment variable `OAUTH2_PROXY_GITLAB_GROUP` is now `OAUTH2_PROXY_GITLAB_GROUPS`

## Changes since v5.1.1

- [GHSA-5m6c-jp6f-2vcv](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-5m6c-jp6f-2vcv) New OpenRedirect cases have been found (@JoelSpeed)
- [#639](https://github.com/oauth2-proxy/oauth2-proxy/pull/639) Change how gitlab-group is parsed on options (@linuxgemini)
- [#615](https://github.com/oauth2-proxy/oauth2-proxy/pull/615) Kubernetes example based on Kind cluster and Nginx ingress (@EvgeniGordeev)
- [#596](https://github.com/oauth2-proxy/oauth2-proxy/pull/596) Validate Bearer IDTokens in headers with correct provider/extra JWT Verifier (@NickMeves)
- [#620](https://github.com/oauth2-proxy/oauth2-proxy/pull/620) Add HealthCheck middleware (@JoelSpeed)
- [#597](https://github.com/oauth2-proxy/oauth2-proxy/pull/597) Don't log invalid redirect if redirect is empty (@JoelSpeed)
- [#604](https://github.com/oauth2-proxy/oauth2-proxy/pull/604) Add Keycloak local testing environment (@EvgeniGordeev)
- [#539](https://github.com/oauth2-proxy/oauth2-proxy/pull/539) Refactor encryption ciphers and add AES-GCM support (@NickMeves)
- [#601](https://github.com/oauth2-proxy/oauth2-proxy/pull/601) Ensure decrypted user/email are valid UTF8 (@JoelSpeed)
- [#560](https://github.com/oauth2-proxy/oauth2-proxy/pull/560) Fallback to UserInfo is User ID claim not present (@JoelSpeed)
- [#598](https://github.com/oauth2-proxy/oauth2-proxy/pull/598) acr_values no longer sent to IdP when empty (@ScottGuymer)
- [#548](https://github.com/oauth2-proxy/oauth2-proxy/pull/548) Separate logging options out of main options structure (@JoelSpeed)
- [#567](https://github.com/oauth2-proxy/oauth2-proxy/pull/567) Allow health/ping request to be identified via User-Agent (@chkohner)
- [#536](https://github.com/oauth2-proxy/oauth2-proxy/pull/536) Improvements to Session State code (@JoelSpeed)
- [#573](https://github.com/oauth2-proxy/oauth2-proxy/pull/573) Properly parse redis urls for cluster and sentinel connections (@amnay-mo)
- [#574](https://github.com/oauth2-proxy/oauth2-proxy/pull/574) render error page on 502 proxy status (@amnay-mo)
- [#559](https://github.com/oauth2-proxy/oauth2-proxy/pull/559) Rename cookie-domain config to cookie-domains (@JoelSpeed)
- [#569](https://github.com/oauth2-proxy/oauth2-proxy/pull/569) Updated autocompletion for `--` long options. (@Izzette)
- [#489](https://github.com/oauth2-proxy/oauth2-proxy/pull/489) Move Options and Validation to separate packages (@JoelSpeed)
- [#556](https://github.com/oauth2-proxy/oauth2-proxy/pull/556) Remove unintentional auto-padding of secrets that were too short (@NickMeves)
- [#538](https://github.com/oauth2-proxy/oauth2-proxy/pull/538) Refactor sessions/utils.go functionality to other areas (@NickMeves)
- [#503](https://github.com/oauth2-proxy/oauth2-proxy/pull/503) Implements --real-client-ip-header option to select the header from which to obtain a proxied client's IP (@Izzette)
- [#529](https://github.com/oauth2-proxy/oauth2-proxy/pull/529) Add local test environments for testing changes and new features (@JoelSpeed)
- [#537](https://github.com/oauth2-proxy/oauth2-proxy/pull/537) Drop Fallback to Email if User not set (@JoelSpeed)
- [#535](https://github.com/oauth2-proxy/oauth2-proxy/pull/535) Drop support for pre v3.1 cookies (@JoelSpeed)
- [#533](https://github.com/oauth2-proxy/oauth2-proxy/pull/487) Set up code coverage within Travis for Code Climate (@JoelSpeed)
- [#514](https://github.com/oauth2-proxy/oauth2-proxy/pull/514) Add basic string functions to templates (@n-i-x)
- [#524](https://github.com/oauth2-proxy/oauth2-proxy/pull/524) Sign cookies with SHA256 (@NickMeves)
- [#515](https://github.com/oauth2-proxy/oauth2-proxy/pull/515) Drop configure script in favour of native Makefile env and checks (@JoelSpeed)
- [#519](https://github.com/oauth2-proxy/oauth2-proxy/pull/519) Support context in providers (@johejo)
- [#487](https://github.com/oauth2-proxy/oauth2-proxy/pull/487) Switch flags to PFlag to remove StringArray (@JoelSpeed)
- [#484](https://github.com/oauth2-proxy/oauth2-proxy/pull/484) Replace configuration loading with Viper (@JoelSpeed)
- [#499](https://github.com/oauth2-proxy/oauth2-proxy/pull/499) Add `-user-id-claim` to support generic claims in addition to email (@holyjak)
- [#486](https://github.com/oauth2-proxy/oauth2-proxy/pull/486) Add new linters (@johejo)
- [#440](https://github.com/oauth2-proxy/oauth2-proxy/pull/440) Switch Azure AD Graph API to Microsoft Graph API (@johejo)
- [#453](https://github.com/oauth2-proxy/oauth2-proxy/pull/453) Prevent browser caching during auth flow (@johejo)
- [#467](https://github.com/oauth2-proxy/oauth2-proxy/pull/467) Allow OIDC issuer verification to be skipped (@chkohner)
- [#481](https://github.com/oauth2-proxy/oauth2-proxy/pull/481) Update Okta docs (@trevorbox)
- [#474](https://github.com/oauth2-proxy/oauth2-proxy/pull/474) Always log hasMember request error object (@jbielick)
- [#468](https://github.com/oauth2-proxy/oauth2-proxy/pull/468) Implement graceful shutdown and propagate request context (@johejo)
- [#464](https://github.com/oauth2-proxy/oauth2-proxy/pull/464) Migrate to oauth2-proxy/oauth2-proxy (@JoelSpeed)
  - Project renamed from `pusher/oauth2_proxy` to `oauth2-proxy`
  - Move Go import path from `github.com/pusher/oauth2_proxy` to `github.com/oauth2-proxy/oauth2-proxy`
  - Remove Pusher Cloud Team from CODEOWNERS
  - Release images moved to `quay.io/oauth2-proxy/oauth2-proxy`
  - Binaries renamed from `oauth2_proxy` to `oauth2-proxy`
- [#432](https://github.com/oauth2-proxy/oauth2-proxy/pull/432) Update ruby dependencies for documentation (@theobarberbany)
- [#471](https://github.com/oauth2-proxy/oauth2-proxy/pull/471) Add logging in case of invalid redirects (@gargath)
- [#462](https://github.com/oauth2-proxy/oauth2-proxy/pull/462) Allow HTML in banner message (@eritikass)
- [#412](https://github.com/oauth2-proxy/oauth2-proxy/pull/412) Allow multiple cookie domains to be specified (@edahlseng)
- [#413](https://github.com/oauth2-proxy/oauth2-proxy/pull/413) Add -set-basic-auth param to set the Basic Authorization header for upstreams (@morarucostel)
- [#483](https://github.com/oauth2-proxy/oauth2-proxy/pull/483) Warn users when session cookies are split (@JoelSpeed)
- [#488](https://github.com/oauth2-proxy/oauth2-proxy/pull/488) Set-Basic-Auth should default to false (@JoelSpeed)
- [#494](https://github.com/oauth2-proxy/oauth2-proxy/pull/494) Upstream websockets TLS certificate validation now depends on ssl-upstream-insecure-skip-verify (@yaroslavros)
- [#497](https://github.com/oauth2-proxy/oauth2-proxy/pull/497) Restrict access using Github collaborators (@jsclayton)
- [#414](https://github.com/oauth2-proxy/oauth2-proxy/pull/414) Always encrypt sessions regardless of config (@ti-mo)
- [#421](https://github.com/oauth2-proxy/oauth2-proxy/pull/421) Allow logins by usernames even if they do not belong to the specified org and team or collaborators (@yyoshiki41)

# v5.1.1

## Release Highlights

N/A

## Important Notes

- (Security) Fix for [open redirect vulnerability](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-j7px-6hwj-hpjg).
  - A bad actor using encoded whitespace in redirect URIs can redirect a session to another domain

## Breaking Changes

N/A

## Changes since v5.1.0

- [GHSA-j7px-6hwj-hpjg](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-j7px-6hwj-hpjg) Fix Open Redirect Vulnerability with encoded Whitespace characters (@JoelSpeed)

# v5.1.0

## Release Highlights

- Bump to Go 1.14
- Reduced number of Google API requests for group validation
- Support for Redis Cluster
- Support for overriding hosts in hosts file

## Important Notes

- [#335] The session expiry for the OIDC provider is now taken from the Token Response (expires_in) rather than from the id_token (exp)

## Breaking Changes

N/A

## Changes since v5.0.0

- [#450](https://github.com/oauth2-proxy/oauth2-proxy/pull/450) Fix http.Cookie SameSite is not copied (@johejo)
- [#445](https://github.com/oauth2-proxy/oauth2-proxy/pull/445) Expose `acr_values` to all providers (@holyjak)
- [#419](https://github.com/oauth2-proxy/oauth2-proxy/pull/419) Support Go 1.14, upgrade dependencies, upgrade golangci-lint to 1.23.6 (@johejo)
- [#444](https://github.com/oauth2-proxy/oauth2-proxy/pull/444) Support prompt in addition to approval-prompt (@holyjak)
- [#435](https://github.com/oauth2-proxy/oauth2-proxy/pull/435) Fix issue with group validation calling google directory API on every HTTP request (@ericofusco)
- [#400](https://github.com/oauth2-proxy/oauth2-proxy/pull/400) Add `nsswitch.conf` to Docker image to allow hosts file to work (@luketainton)
- [#385](https://github.com/oauth2-proxy/oauth2-proxy/pull/385) Use the `Authorization` header instead of `access_token` for refreshing GitHub Provider sessions (@ibuclaw)
- [#372](https://github.com/oauth2-proxy/oauth2-proxy/pull/372) Allow fallback to secondary verified email address in GitHub provider (@dmnemec)
- [#335](https://github.com/oauth2-proxy/oauth2-proxy/pull/335) OIDC Provider support for empty id_tokens in the access token refresh response (@howzat)
- [#363](https://github.com/oauth2-proxy/oauth2-proxy/pull/363) Extension of Redis Session Store to Support Redis Cluster (@yan-dblinf)
- [#353](https://github.com/oauth2-proxy/oauth2-proxy/pull/353) Fix login page fragment handling after soft reload on Firefox (@ffdybuster)
- [#355](https://github.com/oauth2-proxy/oauth2-proxy/pull/355) Add Client Secret File support for providers that rotate client secret via file system (@pasha-r)
- [#401](https://github.com/oauth2-proxy/oauth2-proxy/pull/401) Give the option to pass email address in the Basic auth header instead of upstream usernames. (@Spindel)
- [#405](https://github.com/oauth2-proxy/oauth2-proxy/pull/405) The `/sign_in` page now honors the `rd` query parameter, fixing the redirect after a successful authentication (@ti-mo)
- [#434](https://github.com/oauth2-proxy/oauth2-proxy/pull/434) Give the option to prefer email address in the username header when using the -pass-user-headers option (@jordancrawfordnz)

# v5.0.0

## Release Highlights

- Disabled CGO (binaries will work regardless og glibc/musl)
- Allow whitelisted redirect ports
- Nextcloud provider support added
- DigitalOcean provider support added

## Important Notes

- (Security) Fix for [open redirect vulnerability](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-qqxw-m5fj-f7gv).. a bad actor using `/\` in redirect URIs can redirect a session to another domain

## Breaking Changes

- [#321](https://github.com/oauth2-proxy/oauth2-proxy/pull/331) Add reverse proxy boolean flag to control whether headers like `X-Real-Ip` are accepted.
  This defaults to false. **Usage behind a reverse proxy will require this flag to be set to avoid logging the reverse proxy IP address**.

## Changes since v4.1.0

- [#331](https://github.com/oauth2-proxy/oauth2-proxy/pull/331) Add reverse proxy setting (@martin-css)
- [#365](https://github.com/oauth2-proxy/oauth2-proxy/pull/365) Build with CGO=0 (@tomelliff)
- [#339](https://github.com/oauth2-proxy/oauth2-proxy/pull/339) Add configuration for cookie 'SameSite' value. (@pgroudas)
- [#347](https://github.com/oauth2-proxy/oauth2-proxy/pull/347) Update keycloak provider configuration documentation. (@sushiMix)
- [#325](https://github.com/oauth2-proxy/oauth2-proxy/pull/325) dist.sh: use sha256sum (@syscll)
- [#179](https://github.com/oauth2-proxy/oauth2-proxy/pull/179) Add Nextcloud provider (@Ramblurr)
- [#280](https://github.com/oauth2-proxy/oauth2-proxy/pull/280) whitelisted redirect domains: add support for whitelisting specific ports or allowing wildcard ports (@kamaln7)
- [#351](https://github.com/oauth2-proxy/oauth2-proxy/pull/351) Add DigitalOcean Auth provider (@kamaln7)

# v4.1.0

## Release Highlights

- Added Keycloak provider
- Build on Go 1.13
- Upgrade Docker image to use Debian Buster
- Added support for FreeBSD builds
- Added new logo
- Added support for GitHub teams

## Important Notes

N/A

## Breaking Changes

N/A

## Changes since v4.0.0

- [#292](https://github.com/oauth2-proxy/oauth2-proxy/pull/292) Added bash >= 4.0 dependency to configure script (@jmfrank63)
- [#227](https://github.com/oauth2-proxy/oauth2-proxy/pull/227) Add Keycloak provider (@Ofinka)
- [#259](https://github.com/oauth2-proxy/oauth2-proxy/pull/259) Redirect to HTTPS (@jmickey)
- [#273](https://github.com/oauth2-proxy/oauth2-proxy/pull/273) Support Go 1.13 (@dio)
- [#275](https://github.com/oauth2-proxy/oauth2-proxy/pull/275) docker: build from debian buster (@syscll)
- [#258](https://github.com/oauth2-proxy/oauth2-proxy/pull/258) Add IDToken for Azure provider (@leyshon)
  - This PR adds the IDToken into the session for the Azure provider allowing requests to a backend to be identified as a specific user. As a consequence, if you are using a cookie to store the session the cookie will now exceed the 4kb size limit and be split into multiple cookies. This can cause problems when using nginx as a proxy, resulting in no cookie being passed at all. Either increase the proxy_buffer_size in nginx or implement the redis session storage (see https://oauth2-proxy.github.io/oauth2-proxy/configuration#redis-storage)
- [#286](https://github.com/oauth2-proxy/oauth2-proxy/pull/286) Requests.go updated with useful error messages (@biotom)
- [#274](https://github.com/oauth2-proxy/oauth2-proxy/pull/274) Supports many github teams with api pagination support (@toshi-miura, @apratina)
- [#302](https://github.com/oauth2-proxy/oauth2-proxy/pull/302) Rewrite dist script (@syscll)
- [#304](https://github.com/oauth2-proxy/oauth2-proxy/pull/304) Add new Logo! :tada: (@JoelSpeed)
- [#300](https://github.com/oauth2-proxy/oauth2-proxy/pull/300) Added userinfo endpoint (@kbabuadze)
- [#309](https://github.com/oauth2-proxy/oauth2-proxy/pull/309) Added support for custom CA when connecting to Redis cache (@lleszczu)
- [#248](https://github.com/oauth2-proxy/oauth2-proxy/pull/248) Fix issue with X-Auth-Request-Redirect header being ignored (@webnard)
- [#314](https://github.com/oauth2-proxy/oauth2-proxy/pull/314) Add redirect capability to sign_out (@costelmoraru)
- [#265](https://github.com/oauth2-proxy/oauth2-proxy/pull/265) Add upstream with static response (@cgroschupp)
- [#317](https://github.com/oauth2-proxy/oauth2-proxy/pull/317) Add build for FreeBSD (@fnkr)
- [#296](https://github.com/oauth2-proxy/oauth2-proxy/pull/296) Allow to override provider's name for sign-in page (@ffdybuster)

# v4.0.0

## Release Highlights

- Documentation is now on a [microsite](https://oauth2-proxy.github.io/oauth2-proxy/)
- Health check logging can now be disabled for quieter logs
- Authorization Header JWTs can now be verified by the proxy to skip authentication for machine users
- Sessions can now be stored in Redis. This reduces refresh failures and uses smaller cookies (Recommended for those using OIDC refreshing)
- Logging overhaul allows customisable logging formats

## Important Notes

- This release includes a number of breaking changes that will require users to
  reconfigure their proxies. Please read the Breaking Changes below thoroughly.

## Breaking Changes

- [#231](https://github.com/oauth2-proxy/oauth2-proxy/pull/231) Rework GitLab provider
  - This PR changes the configuration options for the GitLab provider to use
    a self-hosted instance. You now need to specify a `-oidc-issuer-url` rather than
    explicit `-login-url`, `-redeem-url` and `-validate-url` parameters.
- [#186](https://github.com/oauth2-proxy/oauth2-proxy/pull/186) Make config consistent
  - This PR changes configuration options so that all flags have a config counterpart
    of the same name but with underscores (`_`) in place of hyphens (`-`).
    This change affects the following flags:
  - The `--tls-key` flag is now `--tls-key-file` to be consistent with existing
    file flags and the existing config and environment settings
  - The `--tls-cert` flag is now `--tls-cert-file` to be consistent with existing
    file flags and the existing config and environment settings
    This change affects the following existing configuration options:
  - The `proxy-prefix` option is now `proxy_prefix`.
    This PR changes environment variables so that all flags have an environment
    counterpart of the same name but capitalised, with underscores (`_`) in place
    of hyphens (`-`) and with the prefix `OAUTH2_PROXY_`.
    This change affects the following existing environment variables:
  - The `OAUTH2_SKIP_OIDC_DISCOVERY` environment variable is now `OAUTH2_PROXY_SKIP_OIDC_DISCOVERY`.
  - The `OAUTH2_OIDC_JWKS_URL` environment variable is now `OAUTH2_PROXY_OIDC_JWKS_URL`.
- [#146](https://github.com/oauth2-proxy/oauth2-proxy/pull/146) Use full email address as `User` if the auth response did not contain a `User` field
  - This change modifies the contents of the `X-Forwarded-User` header supplied by the proxy for users where the auth response from the IdP did not contain
    a username.
    In that case, this header used to only contain the local part of the user's email address (e.g. `john.doe` for `john.doe@example.com`) but now contains
    the user's full email address instead.
- [#170](https://github.com/oauth2-proxy/oauth2-proxy/pull/170) Pre-built binary tarballs changed format
  - The pre-built binary tarballs again match the format of the [bitly](https://github.com/bitly/oauth2_proxy) repository, where the unpacked directory
    has the same name as the tarball and the binary is always named `oauth2_proxy`. This was done to restore compatibility with third-party automation
    recipes like https://github.com/jhoblitt/puppet-oauth2_proxy.

## Changes since v3.2.0

- [#234](https://github.com/oauth2-proxy/oauth2-proxy/pull/234) Added option `-ssl-upstream-insecure-skip-validation` to skip validation of upstream SSL certificates (@jansinger)
- [#224](https://github.com/oauth2-proxy/oauth2-proxy/pull/224) Check Google group membership using hasMember to support nested groups and external users (@jpalpant)
- [#231](https://github.com/oauth2-proxy/oauth2-proxy/pull/231) Add optional group membership and email domain checks to the GitLab provider (@Overv)
- [#226](https://github.com/oauth2-proxy/oauth2-proxy/pull/226) Made setting of proxied headers deterministic based on configuration alone (@aeijdenberg)
- [#178](https://github.com/oauth2-proxy/oauth2-proxy/pull/178) Add Silence Ping Logging and Exclude Logging Paths flags (@kskewes)
- [#209](https://github.com/oauth2-proxy/oauth2-proxy/pull/209) Improve docker build caching of layers (@dekimsey)
- [#186](https://github.com/oauth2-proxy/oauth2-proxy/pull/186) Make config consistent (@JoelSpeed)
- [#187](https://github.com/oauth2-proxy/oauth2-proxy/pull/187) Move root packages to pkg folder (@JoelSpeed)
- [#65](https://github.com/oauth2-proxy/oauth2-proxy/pull/65) Improvements to authenticate requests with a JWT bearer token in the `Authorization` header via
  the `-skip-jwt-bearer-token` options. (@brianv0)
  - Additional verifiers can be configured via the `-extra-jwt-issuers` flag if the JWT issuers is either an OpenID provider or has a JWKS URL
    (e.g. `https://example.com/.well-known/jwks.json`).
- [#180](https://github.com/oauth2-proxy/oauth2-proxy/pull/180) Minor refactor of core proxying path (@aeijdenberg).
- [#175](https://github.com/oauth2-proxy/oauth2-proxy/pull/175) Bump go-oidc to v2.0.0 (@aeijdenberg).
  - Includes fix for potential signature checking issue when OIDC discovery is skipped.
- [#155](https://github.com/oauth2-proxy/oauth2-proxy/pull/155) Add RedisSessionStore implementation (@brianv0, @JoelSpeed)
  - Implement flags to configure the redis session store
    - `-session-store-type=redis` Sets the store type to redis
    - `-redis-connection-url` Sets the Redis connection URL
    - `-redis-use-sentinel=true` Enables Redis Sentinel support
    - `-redis-sentinel-master-name` Sets the Sentinel master name, if sentinel is enabled
    - `-redis-sentinel-connection-urls` Defines the Redis Sentinel Connection URLs, if sentinel is enabled
  - Introduces the concept of a session ticket. Tickets are composed of the cookie name, a session ID, and a secret.
  - Redis Sessions are stored encrypted with a per-session secret
  - Added tests for server based session stores
- [#168](https://github.com/oauth2-proxy/oauth2-proxy/pull/168) Drop Go 1.11 support in Travis (@JoelSpeed)
- [#169](https://github.com/oauth2-proxy/oauth2-proxy/pull/169) Update Alpine to 3.9 (@kskewes)
- [#148](https://github.com/oauth2-proxy/oauth2-proxy/pull/148) Implement SessionStore interface within proxy (@JoelSpeed)
- [#147](https://github.com/oauth2-proxy/oauth2-proxy/pull/147) Add SessionStore interfaces and initial implementation (@JoelSpeed)
  - Allows for multiple different session storage implementations including client and server side
  - Adds tests suite for interface to ensure consistency across implementations
  - Refactor some configuration options (around cookies) into packages
- [#114](https://github.com/oauth2-proxy/oauth2-proxy/pull/114), [#154](https://github.com/oauth2-proxy/oauth2-proxy/pull/154) Documentation is now available live at our [docs website](https://oauth2-proxy.github.io/oauth2-proxy/) (@JoelSpeed, @icelynjennings)
- [#146](https://github.com/oauth2-proxy/oauth2-proxy/pull/146) Use full email address as `User` if the auth response did not contain a `User` field (@gargath)
- [#144](https://github.com/oauth2-proxy/oauth2-proxy/pull/144) Use GO 1.12 for ARM builds (@kskewes)
- [#142](https://github.com/oauth2-proxy/oauth2-proxy/pull/142) ARM Docker USER fix (@kskewes)
- [#52](https://github.com/oauth2-proxy/oauth2-proxy/pull/52) Logging Improvements (@MisterWil)
  - Implement flags to configure file logging
    - `-logging-filename` Defines the filename to log to
    - `-logging-max-size` Defines the maximum
    - `-logging-max-age` Defines the maximum age of backups to retain
    - `-logging-max-backups` Defines the maximum number of rollover log files to retain
    - `-logging-compress` Defines if rollover log files should be compressed
    - `-logging-local-time` Defines if logging date and time should be local or UTC
  - Implement two new flags to enable or disable specific logging types
    - `-standard-logging` Enables or disables standard (not request or auth) logging
    - `-auth-logging` Enables or disables auth logging
  - Implement two new flags to customize the logging format
    - `-standard-logging-format` Sets the format for standard logging
    - `-auth-logging-format` Sets the format for auth logging
- [#111](https://github.com/oauth2-proxy/oauth2-proxy/pull/111) Add option for telling where to find a login.gov JWT key file (@timothy-spencer)
- [#170](https://github.com/oauth2-proxy/oauth2-proxy/pull/170) Restore binary tarball contents to be compatible with bitlys original tarballs (@zeha)
- [#185](https://github.com/oauth2-proxy/oauth2-proxy/pull/185) Fix an unsupported protocol scheme error during token validation when using the Azure provider (@jonas)
- [#141](https://github.com/oauth2-proxy/oauth2-proxy/pull/141) Check google group membership based on email address (@bchess)
  - Google Group membership is additionally checked via email address, allowing users outside a GSuite domain to be authorized.
- [#195](https://github.com/oauth2-proxy/oauth2-proxy/pull/195) Add `-banner` flag for overriding the banner line that is displayed (@steakunderscore)
- [#198](https://github.com/oauth2-proxy/oauth2-proxy/pull/198) Switch from gometalinter to golangci-lint (@steakunderscore)
- [#159](https://github.com/oauth2-proxy/oauth2-proxy/pull/159) Add option to skip the OIDC provider verified email check: `--insecure-oidc-allow-unverified-email` (@djfinlay)
- [#210](https://github.com/oauth2-proxy/oauth2-proxy/pull/210) Update base image from Alpine 3.9 to 3.10 (@steakunderscore)
- [#201](https://github.com/oauth2-proxy/oauth2-proxy/pull/201) Add Bitbucket as new OAuth2 provider, accepts email, team and repository permissions to determine authorization (@aledeganopix4d)
  - Implement flags to enable Bitbucket authentication:
    - `-bitbucket-repository` Restrict authorization to users that can access this repository
    - `-bitbucket-team` Restrict authorization to users that are part of this Bitbucket team
- [#211](https://github.com/oauth2-proxy/oauth2-proxy/pull/211) Switch from dep to go modules (@steakunderscore)
- [#145](https://github.com/oauth2-proxy/oauth2-proxy/pull/145) Add support for OIDC UserInfo endpoint email verification (@rtluckie)

# v3.2.0

## Release highlights

- Internal restructure of session state storage to use JSON rather than proprietary scheme
- Added health check options for running on GCP behind a load balancer
- Improved support for protecting websockets
- Added provider for login.gov
- Allow manual configuration of OIDC providers

## Important notes

- Dockerfile user is now non-root, this may break your existing deployment
- In the OIDC provider, when no email is returned, the ID Token subject will be used
  instead of returning an error
- GitHub user emails must now be primary and verified before authenticating

## Changes since v3.1.0

- [#96](https://github.com/bitly/oauth2_proxy/pull/96) Check if email is verified on GitHub (@caarlos0)
- [#110](https://github.com/oauth2-proxy/oauth2-proxy/pull/110) Added GCP healthcheck option (@timothy-spencer)
- [#112](https://github.com/oauth2-proxy/oauth2-proxy/pull/112) Improve websocket support (@gyson)
- [#63](https://github.com/oauth2-proxy/oauth2-proxy/pull/63) Use encoding/json for SessionState serialization (@yaegashi)
  - Use JSON to encode session state to be stored in browser cookies
  - Implement legacy decode function to support existing cookies generated by older versions
  - Add detailed table driven tests in session_state_test.go
- [#120](https://github.com/oauth2-proxy/oauth2-proxy/pull/120) Encrypting user/email from cookie (@costelmoraru)
- [#55](https://github.com/oauth2-proxy/oauth2-proxy/pull/55) Added login.gov provider (@timothy-spencer)
- [#55](https://github.com/oauth2-proxy/oauth2-proxy/pull/55) Added environment variables for all config options (@timothy-spencer)
- [#70](https://github.com/oauth2-proxy/oauth2-proxy/pull/70) Fix handling of splitted cookies (@einfachchr)
- [#92](https://github.com/oauth2-proxy/oauth2-proxy/pull/92) Merge websocket proxy feature from openshift/oauth-proxy (@butzist)
- [#57](https://github.com/oauth2-proxy/oauth2-proxy/pull/57) Fall back to using OIDC Subject instead of Email (@aigarius)
- [#85](https://github.com/oauth2-proxy/oauth2-proxy/pull/85) Use non-root user in docker images (@kskewes)
- [#68](https://github.com/oauth2-proxy/oauth2-proxy/pull/68) forward X-Auth-Access-Token header (@davidholsgrove)
- [#41](https://github.com/oauth2-proxy/oauth2-proxy/pull/41) Added option to manually specify OIDC endpoints instead of relying on discovery
- [#83](https://github.com/oauth2-proxy/oauth2-proxy/pull/83) Add `id_token` refresh to Google provider (@leki75)
- [#10](https://github.com/oauth2-proxy/oauth2-proxy/pull/10) fix redirect url param handling (@dt-rush)
- [#122](https://github.com/oauth2-proxy/oauth2-proxy/pull/122) Expose -cookie-path as configuration parameter (@costelmoraru)
- [#124](https://github.com/oauth2-proxy/oauth2-proxy/pull/124) Use Go 1.12 for testing and build environments (@syscll)

# v3.1.0

## Release highlights

- Introduction of ARM releases and and general improvements to Docker builds
- Improvements to OIDC provider allowing pass-through of ID Tokens
- Multiple redirect domains can now be whitelisted
- Streamed responses are now flushed periodically

## Important notes

- If you have been using [#bitly/621](https://github.com/bitly/oauth2_proxy/pull/621)
  and have cookies larger than the 4kb limit,
  the cookie splitting pattern has changed and now uses `_` in place of `-` when
  indexing cookies.
  This will force users to reauthenticate the first time they use `v3.1.0`.
- Streamed responses will now be flushed every 1 second by default.
  Previously streamed responses were flushed only when the buffer was full.
  To retain the old behaviour set `--flush-interval=0`.
  See [#23](https://github.com/oauth2-proxy/oauth2-proxy/pull/23) for further details.

## Changes since v3.0.0

- [#14](https://github.com/oauth2-proxy/oauth2-proxy/pull/14) OIDC ID Token, Authorization Headers, Refreshing and Verification (@joelspeed)
  - Implement `pass-authorization-header` and `set-authorization-header` flags
  - Implement token refreshing in OIDC provider
  - Split cookies larger than 4k limit into multiple cookies
  - Implement token validation in OIDC provider
- [#15](https://github.com/oauth2-proxy/oauth2-proxy/pull/15) WhitelistDomains (@joelspeed)
  - Add `--whitelist-domain` flag to allow redirection to approved domains after OAuth flow
- [#21](https://github.com/oauth2-proxy/oauth2-proxy/pull/21) Docker Improvement (@yaegashi)
  - Move Docker base image from debian to alpine
  - Install ca-certificates in docker image
- [#23](https://github.com/oauth2-proxy/oauth2-proxy/pull/23) Flushed streaming responses
  - Long-running upstream responses will get flushed every <timeperiod> (1 second by default)
- [#24](https://github.com/oauth2-proxy/oauth2-proxy/pull/24) Redirect fix (@agentgonzo)
  - After a successful login, you will be redirected to your original URL rather than /
- [#35](https://github.com/oauth2-proxy/oauth2-proxy/pull/35) arm and arm64 binary releases (@kskewes)
  - Add armv6 and arm64 to Makefile `release` target
- [#37](https://github.com/oauth2-proxy/oauth2-proxy/pull/37) cross build arm and arm64 docker images (@kskewes)

# v3.0.0

Adoption of OAuth2_Proxy by Pusher.
Project was hard forked and tidied however no logical changes have occurred since
v2.2 as released by Bitly.

## Changes since v2.2:

- [#7](https://github.com/oauth2-proxy/oauth2-proxy/pull/7) Migration to Pusher (@joelspeed)
  - Move automated build to debian base image
  - Add Makefile
    - Update CI to run `make test`
    - Update Dockerfile to use `make clean oauth2_proxy`
    - Update `VERSION` parameter to be set by `ldflags` from Git Status
    - Remove lint and test scripts
  - Remove Go v1.8.x from Travis CI testing
  - Add CODEOWNERS file
  - Add CONTRIBUTING guide
  - Add Issue and Pull Request templates
  - Add Dockerfile
  - Fix fsnotify import
  - Update README to reflect new repository ownership
  - Update CI scripts to separate linting and testing
    - Now using `gometalinter` for linting
  - Move Go import path from `github.com/bitly/oauth2_proxy` to `github.com/pusher/oauth2_proxy`
  - Repository forked on 27/11/18
    - README updated to include note that this repository is forked
    - CHANGLOG created to track changes to repository from original fork
