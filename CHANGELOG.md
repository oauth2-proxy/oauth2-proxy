# Vx.x.x (Pre-release)

## Important Notes

## Breaking Changes

- [#321](https://github.com/pusher/oauth2_proxy/pull/331) Add reverse proxy boolean flag to control whether headers like `X-Real-Ip` are accepted.
  This defaults to false. **Usage behind a reverse proxy will require this flag to be set to avoid logging the reverse proxy IP address**.

## Changes since v4.1.0

- [#339](https://github.com/pusher/oauth2_proxy/pull/339) Add configuration for cookie 'SameSite' value. (@pgroudas)
- [#347](https://github.com/pusher/oauth2_proxy/pull/347) Update keycloak provider configuration documentation
- [#325](https://github.com/pusher/oauth2_proxy/pull/325) dist.sh: use sha256sum (@syscll)
- [#179](https://github.com/pusher/oauth2_proxy/pull/179) Add Nextcloud provider (@Ramblurr)
- [#280](https://github.com/pusher/oauth2_proxy/pull/280) whitelisted redirect domains: add support for whitelisting specific ports or allowing wildcard ports (@kamaln7)
- [#351](https://github.com/pusher/oauth2_proxy/pull/351) Add DigitalOcean Auth provider (@kamaln7)

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
- [#292](https://github.com/pusher/oauth2_proxy/pull/292) Added bash >= 4.0 dependency to configure script (@jmfrank63)
- [#227](https://github.com/pusher/oauth2_proxy/pull/227) Add Keycloak provider (@Ofinka)
- [#259](https://github.com/pusher/oauth2_proxy/pull/259) Redirect to HTTPS (@jmickey)
- [#273](https://github.com/pusher/oauth2_proxy/pull/273) Support Go 1.13 (@dio)
- [#275](https://github.com/pusher/oauth2_proxy/pull/275) docker: build from debian buster (@syscll)
- [#258](https://github.com/pusher/oauth2_proxy/pull/258) Add IDToken for Azure provider (@leyshon)
  - This PR adds the IDToken into the session for the Azure provider allowing requests to a backend to be identified as a specific user. As a consequence, if you are using a cookie to store the session the cookie will now exceed the 4kb size limit and be split into multiple cookies. This can cause problems when using nginx as a proxy, resulting in no cookie being passed at all. Either increase the proxy_buffer_size in nginx or implement the redis session storage (see https://pusher.github.io/oauth2_proxy/configuration#redis-storage)
- [#286](https://github.com/pusher/oauth2_proxy/pull/286) Requests.go updated with useful error messages (@biotom)
- [#274](https://github.com/pusher/oauth2_proxy/pull/274) Supports many github teams with api pagination support (@toshi-miura, @apratina)
- [#302](https://github.com/pusher/oauth2_proxy/pull/302) Rewrite dist script (@syscll)
- [#304](https://github.com/pusher/oauth2_proxy/pull/304) Add new Logo! :tada: (@JoelSpeed)
- [#300](https://github.com/pusher/oauth2_proxy/pull/300) Added userinfo endpoint (@kbabuadze)
- [#309](https://github.com/pusher/oauth2_proxy/pull/309) Added support for custom CA when connecting to Redis cache (@lleszczu)
- [#248](https://github.com/pusher/oauth2_proxy/pull/248) Fix issue with X-Auth-Request-Redirect header being ignored (@webnard)
- [#314](https://github.com/pusher/oauth2_proxy/pull/314) Add redirect capability to sign_out (@costelmoraru)
- [#265](https://github.com/pusher/oauth2_proxy/pull/265) Add upstream with static response (@cgroschupp)
- [#317](https://github.com/pusher/oauth2_proxy/pull/317) Add build for FreeBSD (@fnkr)
- [#296](https://github.com/pusher/oauth2_proxy/pull/296) Allow to override provider's name for sign-in page (@ffdybuster)

# v4.0.0

## Release Highlights
- Documentation is now on a [microsite](https://pusher.github.io/oauth2_proxy/)
- Health check logging can now be disabled for quieter logs
- Authorization Header JWTs can now be verified by the proxy to skip authentication for machine users
- Sessions can now be stored in Redis. This reduces refresh failures and uses smaller cookies (Recommended for those using OIDC refreshing)
- Logging overhaul allows customisable logging formats

## Important Notes
- This release includes a number of breaking changes that will require users to
reconfigure their proxies. Please read the Breaking Changes below thoroughly.

## Breaking Changes

- [#231](https://github.com/pusher/oauth2_proxy/pull/231) Rework GitLab provider
  - This PR changes the configuration options for the GitLab provider to use
  a self-hosted instance. You now need to specify a `-oidc-issuer-url` rather than
  explicit `-login-url`, `-redeem-url` and `-validate-url` parameters.
- [#186](https://github.com/pusher/oauth2_proxy/pull/186) Make config consistent
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
- [#146](https://github.com/pusher/oauth2_proxy/pull/146) Use full email address as `User` if the auth response did not contain a `User` field
  - This change modifies the contents of the `X-Forwarded-User` header supplied by the proxy for users where the auth response from the IdP did not contain
    a username.
    In that case, this header used to only contain the local part of the user's email address (e.g. `john.doe` for `john.doe@example.com`) but now contains
    the user's full email address instead.
- [#170](https://github.com/pusher/oauth2_proxy/pull/170) Pre-built binary tarballs changed format
  - The pre-built binary tarballs again match the format of the [bitly](https://github.com/bitly/oauth2_proxy) repository, where the unpacked directory
    has the same name as the tarball and the binary is always named `oauth2_proxy`. This was done to restore compatibility with third-party automation
    recipes like https://github.com/jhoblitt/puppet-oauth2_proxy.

## Changes since v3.2.0

- [#234](https://github.com/pusher/oauth2_proxy/pull/234) Added option `-ssl-upstream-insecure-skip-validation` to skip validation of upstream SSL certificates (@jansinger)
- [#224](https://github.com/pusher/oauth2_proxy/pull/224) Check Google group membership using hasMember to support nested groups and external users (@jpalpant)
- [#231](https://github.com/pusher/oauth2_proxy/pull/231) Add optional group membership and email domain checks to the GitLab provider (@Overv)
- [#226](https://github.com/pusher/oauth2_proxy/pull/226) Made setting of proxied headers deterministic based on configuration alone (@aeijdenberg)
- [#178](https://github.com/pusher/oauth2_proxy/pull/178) Add Silence Ping Logging and Exclude Logging Paths flags (@kskewes)
- [#209](https://github.com/pusher/oauth2_proxy/pull/209) Improve docker build caching of layers (@dekimsey)
- [#186](https://github.com/pusher/oauth2_proxy/pull/186) Make config consistent (@JoelSpeed)
- [#187](https://github.com/pusher/oauth2_proxy/pull/187) Move root packages to pkg folder (@JoelSpeed)
- [#65](https://github.com/pusher/oauth2_proxy/pull/65) Improvements to authenticate requests with a JWT bearer token in the `Authorization` header via
  the `-skip-jwt-bearer-token` options. (@brianv0)
  - Additional verifiers can be configured via the `-extra-jwt-issuers` flag if the JWT issuers is either an OpenID provider or has a JWKS URL
  (e.g. `https://example.com/.well-known/jwks.json`).
- [#180](https://github.com/pusher/oauth2_proxy/pull/180) Minor refactor of core proxying path (@aeijdenberg).
- [#175](https://github.com/pusher/oauth2_proxy/pull/175) Bump go-oidc to v2.0.0 (@aeijdenberg).
  - Includes fix for potential signature checking issue when OIDC discovery is skipped.
- [#155](https://github.com/pusher/oauth2_proxy/pull/155) Add RedisSessionStore implementation (@brianv0, @JoelSpeed)
  - Implement flags to configure the redis session store
    - `-session-store-type=redis` Sets the store type to redis
    - `-redis-connection-url` Sets the Redis connection URL
    - `-redis-use-sentinel=true` Enables Redis Sentinel support
    - `-redis-sentinel-master-name` Sets the Sentinel master name, if sentinel is enabled
    - `-redis-sentinel-connection-urls` Defines the Redis Sentinel Connection URLs, if sentinel is enabled
  - Introduces the concept of a session ticket. Tickets are composed of the cookie name, a session ID, and a secret.
  - Redis Sessions are stored encrypted with a per-session secret
  - Added tests for server based session stores
- [#168](https://github.com/pusher/oauth2_proxy/pull/168) Drop Go 1.11 support in Travis (@JoelSpeed)
- [#169](https://github.com/pusher/oauth2_proxy/pull/169) Update Alpine to 3.9 (@kskewes)
- [#148](https://github.com/pusher/oauth2_proxy/pull/148) Implement SessionStore interface within proxy (@JoelSpeed)
- [#147](https://github.com/pusher/oauth2_proxy/pull/147) Add SessionStore interfaces and initial implementation (@JoelSpeed)
  - Allows for multiple different session storage implementations including client and server side
  - Adds tests suite for interface to ensure consistency across implementations
  - Refactor some configuration options (around cookies) into packages
- [#114](https://github.com/pusher/oauth2_proxy/pull/114), [#154](https://github.com/pusher/oauth2_proxy/pull/154) Documentation is now available live at our [docs website](https://pusher.github.io/oauth2_proxy/) (@JoelSpeed, @icelynjennings)
- [#146](https://github.com/pusher/oauth2_proxy/pull/146) Use full email address as `User` if the auth response did not contain a `User` field (@gargath)
- [#144](https://github.com/pusher/oauth2_proxy/pull/144) Use GO 1.12 for ARM builds (@kskewes)
- [#142](https://github.com/pusher/oauth2_proxy/pull/142) ARM Docker USER fix (@kskewes)
- [#52](https://github.com/pusher/oauth2_proxy/pull/52) Logging Improvements (@MisterWil)
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
- [#111](https://github.com/pusher/oauth2_proxy/pull/111) Add option for telling where to find a login.gov JWT key file (@timothy-spencer)
- [#170](https://github.com/pusher/oauth2_proxy/pull/170) Restore binary tarball contents to be compatible with bitlys original tarballs (@zeha)
- [#185](https://github.com/pusher/oauth2_proxy/pull/185) Fix an unsupported protocol scheme error during token validation when using the Azure provider (@jonas)
- [#141](https://github.com/pusher/oauth2_proxy/pull/141) Check google group membership based on email address (@bchess)
  - Google Group membership is additionally checked via email address, allowing users outside a GSuite domain to be authorized.
- [#195](https://github.com/pusher/oauth2_proxy/pull/195) Add `-banner` flag for overriding the banner line that is displayed (@steakunderscore)
- [#198](https://github.com/pusher/oauth2_proxy/pull/198) Switch from gometalinter to golangci-lint (@steakunderscore)
- [#159](https://github.com/pusher/oauth2_proxy/pull/159) Add option to skip the OIDC provider verified email check: `--insecure-oidc-allow-unverified-email` (@djfinlay)
- [#210](https://github.com/pusher/oauth2_proxy/pull/210) Update base image from Alpine 3.9 to 3.10 (@steakunderscore)
- [#201](https://github.com/pusher/oauth2_proxy/pull/201) Add Bitbucket as new OAuth2 provider, accepts email, team and repository permissions to determine authorization (@aledeganopix4d)
  - Implement flags to enable Bitbucket authentication:
    - `-bitbucket-repository` Restrict authorization to users that can access this repository
    - `-bitbucket-team` Restrict authorization to users that are part of this Bitbucket team
- [#211](https://github.com/pusher/oauth2_proxy/pull/211) Switch from dep to go modules (@steakunderscore)
- [#145](https://github.com/pusher/oauth2_proxy/pull/145) Add support for OIDC UserInfo endpoint email verification (@rtluckie)

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
- [#110](https://github.com/pusher/oauth2_proxy/pull/110) Added GCP healthcheck option (@timothy-spencer)
- [#112](https://github.com/pusher/oauth2_proxy/pull/112) Improve websocket support (@gyson)
- [#63](https://github.com/pusher/oauth2_proxy/pull/63) Use encoding/json for SessionState serialization (@yaegashi)
  - Use JSON to encode session state to be stored in browser cookies
  - Implement legacy decode function to support existing cookies generated by older versions
  - Add detailed table driven tests in session_state_test.go
- [#120](https://github.com/pusher/oauth2_proxy/pull/120) Encrypting user/email from cookie (@costelmoraru)
- [#55](https://github.com/pusher/oauth2_proxy/pull/55) Added login.gov provider (@timothy-spencer)
- [#55](https://github.com/pusher/oauth2_proxy/pull/55) Added environment variables for all config options (@timothy-spencer)
- [#70](https://github.com/pusher/oauth2_proxy/pull/70) Fix handling of splitted cookies (@einfachchr)
- [#92](https://github.com/pusher/oauth2_proxy/pull/92) Merge websocket proxy feature from openshift/oauth-proxy (@butzist)
- [#57](https://github.com/pusher/oauth2_proxy/pull/57) Fall back to using OIDC Subject instead of Email (@aigarius)
- [#85](https://github.com/pusher/oauth2_proxy/pull/85) Use non-root user in docker images (@kskewes)
- [#68](https://github.com/pusher/oauth2_proxy/pull/68) forward X-Auth-Access-Token header (@davidholsgrove)
- [#41](https://github.com/pusher/oauth2_proxy/pull/41) Added option to manually specify OIDC endpoints instead of relying on discovery
- [#83](https://github.com/pusher/oauth2_proxy/pull/83) Add `id_token` refresh to Google provider (@leki75)
- [#10](https://github.com/pusher/oauth2_proxy/pull/10) fix redirect url param handling (@dt-rush)
- [#122](https://github.com/pusher/oauth2_proxy/pull/122) Expose -cookie-path as configuration parameter (@costelmoraru)
- [#124](https://github.com/pusher/oauth2_proxy/pull/124) Use Go 1.12 for testing and build environments (@syscll)

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
  See [#23](https://github.com/pusher/oauth2_proxy/pull/23) for further details.

## Changes since v3.0.0

- [#14](https://github.com/pusher/oauth2_proxy/pull/14) OIDC ID Token, Authorization Headers, Refreshing and Verification (@joelspeed)
  - Implement `pass-authorization-header` and `set-authorization-header` flags
  - Implement token refreshing in OIDC provider
  - Split cookies larger than 4k limit into multiple cookies
  - Implement token validation in OIDC provider
- [#15](https://github.com/pusher/oauth2_proxy/pull/15) WhitelistDomains (@joelspeed)
  - Add `--whitelist-domain` flag to allow redirection to approved domains after OAuth flow
- [#21](https://github.com/pusher/oauth2_proxy/pull/21) Docker Improvement (@yaegashi)
  - Move Docker base image from debian to alpine
  - Install ca-certificates in docker image
- [#23](https://github.com/pusher/oauth2_proxy/pull/23) Flushed streaming responses
  - Long-running upstream responses will get flushed every <timeperiod> (1 second by default)
- [#24](https://github.com/pusher/oauth2_proxy/pull/24) Redirect fix (@agentgonzo)
  - After a successful login, you will be redirected to your original URL rather than /
- [#35](https://github.com/pusher/oauth2_proxy/pull/35) arm and arm64 binary releases (@kskewes)
  - Add armv6 and arm64 to Makefile `release` target
- [#37](https://github.com/pusher/oauth2_proxy/pull/37) cross build arm and arm64 docker images (@kskewes)

# v3.0.0

Adoption of OAuth2_Proxy by Pusher.
Project was hard forked and tidied however no logical changes have occurred since
v2.2 as released by Bitly.

## Changes since v2.2:

- [#7](https://github.com/pusher/oauth2_proxy/pull/7) Migration to Pusher (@joelspeed)
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
