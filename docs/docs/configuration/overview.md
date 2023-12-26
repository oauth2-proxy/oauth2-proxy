---
id: overview
title: Overview
---

`oauth2-proxy` can be configured via [command line options](#command-line-options), [environment variables](#environment-variables) or [config file](#config-file) (in decreasing order of precedence, i.e. command line options will overwrite environment variables and environment variables will overwrite configuration file settings).

### Command Line Options

| Option | Type | Description | Default |
| ------ | ---- | ----------- | ------- |
| `--acr-values` | string | optional, see [docs](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html#acrValues) | `""` |
| `--allow-query-semicolons` | bool | allow the use of semicolons in query args ([required for some legacy applications](https://github.com/golang/go/issues/25192)) | `false` |
| `--api-route` | string \| list | return HTTP 401 instead of redirecting to authentication server if token is not valid. Format: path_regex | |
| `--approval-prompt` | string | OAuth approval_prompt | `"force"` |
| `--auth-logging` | bool | Log authentication attempts | true |
| `--auth-logging-format` | string | Template for authentication log lines | see [Logging Configuration](#logging-configuration) |
| `--authenticated-emails-file` | string | authenticate against emails via file (one per line) | |
| `--azure-tenant` | string | go to a tenant-specific or common (tenant-independent) endpoint. | `"common"` |
| `--basic-auth-password` | string | the password to set when passing the HTTP Basic Auth header | |
| `--client-id` | string | the OAuth Client ID, e.g. `"123456.apps.googleusercontent.com"` | |
| `--client-secret` | string | the OAuth Client Secret | |
| `--client-secret-file` | string | the file with OAuth Client Secret | |
| `--code-challenge-method` | string | use PKCE code challenges with the specified method. Either 'plain' or 'S256' (recommended) | |
| `--config` | string | path to config file | |
| `--cookie-domain` | string \| list | Optional cookie domains to force cookies to (e.g. `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match). | |
| `--cookie-expire` | duration | expire timeframe for cookie. If set to 0, cookie becomes a session-cookie which will expire when the browser is closed. | 168h0m0s |
| `--cookie-httponly` | bool | set HttpOnly cookie flag | true |
| `--cookie-name` | string | the name of the cookie that the oauth_proxy creates. Should be changed to use a [cookie prefix](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes) (`__Host-` or `__Secure-`) if `--cookie-secure` is set. | `"_oauth2_proxy"` |
| `--cookie-path` | string | an optional cookie path to force cookies to (e.g. `/poc/`) | `"/"` |
| `--cookie-refresh` | duration | refresh the cookie after this duration; `0` to disable; not supported by all providers&nbsp;\[[1](#footnote1)\] | |
| `--cookie-secret` | string | the seed string for secure cookies (optionally base64 encoded) | |
| `--cookie-secure` | bool | set [secure (HTTPS only) cookie flag](https://owasp.org/www-community/controls/SecureFlag) | true |
| `--cookie-samesite` | string | set SameSite cookie attribute (`"lax"`, `"strict"`, `"none"`, or `""`). | `""` |
| `--cookie-csrf-per-request` | bool | Enable having different CSRF cookies per request, making it possible to have parallel requests. | false |
| `--cookie-csrf-expire` | duration | expire timeframe for CSRF cookie | 15m |
| `--custom-templates-dir` | string | path to custom html templates | |
| `--custom-sign-in-logo` | string | path or a URL to an custom image for the sign_in page logo. Use `"-"` to disable default logo. |
| `--display-htpasswd-form` | bool | display username / password login form if an htpasswd file is provided | true |
| `--email-domain` | string \| list | authenticate emails with the specified domain (may be given multiple times). Use `*` to authenticate any email | |
| `--errors-to-info-log` | bool | redirects error-level logging to default log channel instead of stderr | false |
| `--extra-jwt-issuers` | string | if `--skip-jwt-bearer-tokens` is set, a list of extra JWT `issuer=audience` (see a token's `iss`, `aud` fields) pairs (where the issuer URL has a `.well-known/openid-configuration` or a `.well-known/jwks.json`) | |
| `--exclude-logging-path` | string | comma separated list of paths to exclude from logging, e.g. `"/ping,/path2"` |`""` (no paths excluded) |
| `--flush-interval` | duration | period between flushing response buffers when streaming responses | `"1s"` |
| `--force-https` | bool | enforce https redirect | `false` |
| `--force-json-errors` | bool | force JSON errors instead of HTTP error pages or redirects | `false` |
| `--banner` | string | custom (html) banner string. Use `"-"` to disable default banner. | |
| `--footer` | string | custom (html) footer string. Use `"-"` to disable default footer. | |
| `--github-org` | string | restrict logins to members of this organisation | |
| `--github-team` | string | restrict logins to members of any of these teams (slug), separated by a comma | |
| `--github-repo` | string | restrict logins to collaborators of this repository formatted as `orgname/repo` | |
| `--github-token` | string | the token to use when verifying repository collaborators (must have push access to the repository) | |
| `--github-user` | string \| list | To allow users to login by username even if they do not belong to the specified org and team or collaborators | |
| `--gitlab-group` | string \| list | restrict logins to members of any of these groups (slug), separated by a comma | |
| `--gitlab-projects` | string \| list | restrict logins to members of any of these projects (may be given multiple times) formatted as `orgname/repo=accesslevel`. Access level should be a value matching [Gitlab access levels](https://docs.gitlab.com/ee/api/members.html#valid-access-levels), defaulted to 20 if absent | |
| `--google-admin-email` | string | the google admin to impersonate for api calls | |
| `--google-group` | string | restrict logins to members of this google group (may be given multiple times). | |
| `--google-service-account-json` | string | the path to the service account json credentials | |
| `--google-use-application-default-credentials` | bool | use application default credentials instead of service account json (i.e. GKE Workload Identity) | |
| `--google-target-principal` | bool | the target principal to impersonate when using ADC | defaults to the service account configured for ADC |
| `--htpasswd-file` | string | additionally authenticate against a htpasswd file. Entries must be created with `htpasswd -B` for bcrypt encryption | |
| `--htpasswd-user-group` | string \| list | the groups to be set on sessions for htpasswd users | |
| `--http-address` | string | `[http://]<addr>:<port>` or `unix://<path>` to listen on for HTTP clients. Square brackets are required for ipv6 address, e.g. `http://[::1]:4180` | `"127.0.0.1:4180"` |
| `--https-address` | string | `[https://]<addr>:<port>` to listen on for HTTPS clients. Square brackets are required for ipv6 address, e.g. `https://[::1]:443` | `":443"` |
| `--logging-compress` | bool | Should rotated log files be compressed using gzip | false |
| `--logging-filename` | string | File to log requests to, empty for `stdout` | `""` (stdout) |
| `--logging-local-time` | bool | Use local time in log files and backup filenames instead of UTC | true (local time) |
| `--logging-max-age` | int | Maximum number of days to retain old log files | 7 |
| `--logging-max-backups` | int | Maximum number of old log files to retain; 0 to disable | 0 |
| `--logging-max-size` | int | Maximum size in megabytes of the log file before rotation | 100 |
| `--jwt-key` | string | private key in PEM format used to sign JWT, so that you can say something like `--jwt-key="${OAUTH2_PROXY_JWT_KEY}"`: required by login.gov | |
| `--jwt-key-file` | string | path to the private key file in PEM format used to sign the JWT so that you can say something like `--jwt-key-file=/etc/ssl/private/jwt_signing_key.pem`: required by login.gov | |
| `--login-url` | string | Authentication endpoint | |
| `--insecure-oidc-allow-unverified-email` | bool | don't fail if an email address in an id_token is not verified | false |
| `--insecure-oidc-skip-issuer-verification` | bool | allow the OIDC issuer URL to differ from the expected (currently required for Azure multi-tenant compatibility) | false |
| `--insecure-oidc-skip-nonce` | bool | skip verifying the OIDC ID Token's nonce claim | true |
| `--oidc-issuer-url` | string | the OpenID Connect issuer URL, e.g. `"https://accounts.google.com"` | |
| `--oidc-jwks-url` | string | OIDC JWKS URI for token verification; required if OIDC discovery is disabled | |
| `--oidc-email-claim` | string | which OIDC claim contains the user's email | `"email"` |
| `--oidc-groups-claim` | string | which OIDC claim contains the user groups | `"groups"` |
| `--oidc-audience-claim` | string | which OIDC claim contains the audience | `"aud"` |
| `--oidc-extra-audience` | string \| list | additional audiences which are allowed to pass verification | `"[]"` |
| `--pass-access-token` | bool | pass OAuth access_token to upstream via X-Forwarded-Access-Token header. When used with `--set-xauthrequest` this adds the X-Auth-Request-Access-Token header to the response | false |
| `--pass-authorization-header` | bool | pass OIDC IDToken to upstream via Authorization Bearer header | false |
| `--pass-basic-auth` | bool | pass HTTP Basic Auth, X-Forwarded-User, X-Forwarded-Email and X-Forwarded-Preferred-Username information to upstream | true |
| `--prefer-email-to-user` | bool | Prefer to use the Email address as the Username when passing information to upstream. Will only use Username if Email is unavailable, e.g. htaccess authentication. Used in conjunction with `--pass-basic-auth` and `--pass-user-headers` | false |
| `--pass-host-header` | bool | pass the request Host Header to upstream | true |
| `--pass-user-headers` | bool | pass X-Forwarded-User, X-Forwarded-Groups, X-Forwarded-Email and X-Forwarded-Preferred-Username information to upstream | true |
| `--profile-url` | string | Profile access endpoint | |
| `--prompt` | string | [OIDC prompt](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest); if present, `approval-prompt` is ignored | `""` |
| `--provider` | string | OAuth provider | google |
| `--provider-ca-file` | string \| list | Paths to CA certificates that should be used when connecting to the provider. If not specified, the default Go trust sources are used instead. |
| `--use-system-trust-store` | bool | Determines if `provider-ca-file` files and the system trust store are used. If set to true, your custom CA files and the system trust store are used otherwise only your custom CA files. | false |
| `--provider-display-name` | string | Override the provider's name with the given string; used for the sign-in page | (depends on provider) |
| `--ping-path` | string | the ping endpoint that can be used for basic health checks | `"/ping"` |
| `--ping-user-agent` | string | a User-Agent that can be used for basic health checks | `""` (don't check user agent) |
| `--ready-path` | string | the ready endpoint that can be used for deep health checks | `"/ready"` |
| `--metrics-address` | string | the address prometheus metrics will be scraped from | `""` |
| `--proxy-prefix` | string | the url root path that this proxy should be nested under (e.g. /`<oauth2>/sign_in`) | `"/oauth2"` |
| `--proxy-websockets` | bool | enables WebSocket proxying | true |
| `--pubjwk-url` | string | JWK pubkey access endpoint: required by login.gov | |
| `--real-client-ip-header` | string | Header used to determine the real IP of the client, requires `--reverse-proxy` to be set (one of: X-Forwarded-For, X-Real-IP, or X-ProxyUser-IP) | X-Real-IP |
| `--redeem-url` | string | Token redemption endpoint | |
| `--redirect-url` | string | the OAuth Redirect URL, e.g. `"https://internalapp.yourcompany.com/oauth2/callback"` | |
| `--relative-redirect-url` | bool | allow relative OAuth Redirect URL.` | |
| `--redis-cluster-connection-urls` | string \| list | List of Redis cluster connection URLs (e.g. `redis://HOST[:PORT]`). Used in conjunction with `--redis-use-cluster` | |
| `--redis-connection-url` | string | URL of redis server for redis session storage (e.g. `redis://HOST[:PORT]`) | |
| `--redis-insecure-skip-tls-verify` | bool | skip TLS verification when connecting to Redis | false |
| `--redis-password` | string | Redis password. Applicable for all Redis configurations. Will override any password set in `--redis-connection-url` | |
| `--redis-sentinel-password` | string | Redis sentinel password. Used only for sentinel connection; any redis node passwords need to use `--redis-password` | |
| `--redis-sentinel-master-name` | string | Redis sentinel master name. Used in conjunction with `--redis-use-sentinel` | |
| `--redis-sentinel-connection-urls` | string \| list | List of Redis sentinel connection URLs (e.g. `redis://HOST[:PORT]`). Used in conjunction with `--redis-use-sentinel` | |
| `--redis-use-cluster` | bool | Connect to redis cluster. Must set `--redis-cluster-connection-urls` to use this feature | false |
| `--redis-use-sentinel` | bool | Connect to redis via sentinels. Must set `--redis-sentinel-master-name` and `--redis-sentinel-connection-urls` to use this feature | false |
| `--redis-connection-idle-timeout` | int | Redis connection idle timeout seconds. If Redis [timeout](https://redis.io/docs/reference/clients/#client-timeouts) option is set to non-zero, the `--redis-connection-idle-timeout` must be less than Redis timeout option. Example: if either redis.conf includes `timeout 15` or using `CONFIG SET timeout 15` the `--redis-connection-idle-timeout` must be at least `--redis-connection-idle-timeout=14` | 0 |
| `--request-id-header` | string | Request header to use as the request ID in logging | X-Request-Id |
| `--request-logging` | bool | Log requests | true |
| `--request-logging-format` | string | Template for request log lines | see [Logging Configuration](#logging-configuration) |
| `--resource` | string | The resource that is protected (Azure AD only) | |
| `--reverse-proxy` | bool | are we running behind a reverse proxy, controls whether headers like X-Real-IP are accepted and allows X-Forwarded-{Proto,Host,Uri} headers to be used on redirect selection | false |
| `--scope` | string | OAuth scope specification | |
| `--session-cookie-minimal` | bool | strip OAuth tokens from cookie session stores if they aren't needed (cookie session store only) | false |
| `--session-store-type` | string | [Session data storage backend](sessions.md); redis or cookie | cookie |
| `--set-xauthrequest` | bool | set X-Auth-Request-User, X-Auth-Request-Groups, X-Auth-Request-Email and X-Auth-Request-Preferred-Username response headers (useful in Nginx auth_request mode). When used with `--pass-access-token`, X-Auth-Request-Access-Token is added to response headers. | false |
| `--set-authorization-header` | bool | set Authorization Bearer response header (useful in Nginx auth_request mode) | false |
| `--set-basic-auth` | bool | set HTTP Basic Auth information in response (useful in Nginx auth_request mode) | false |
| `--show-debug-on-error` | bool | show detailed error information on error pages (WARNING: this may contain sensitive information - do not use in production) | false |
| `--signature-key` | string | GAP-Signature request signature key (algorithm:secretkey) | |
| `--silence-ping-logging` | bool | disable logging of requests to ping & ready endpoints | false |
| `--skip-auth-preflight` | bool | will skip authentication for OPTIONS requests | false |
| `--skip-auth-regex` | string \| list | (DEPRECATED for `--skip-auth-route`) bypass authentication for requests paths that match (may be given multiple times) | |
| `--skip-auth-route` | string \| list | bypass authentication for requests that match the method & path. Format: method=path_regex OR method!=path_regex. For all methods: path_regex OR !=path_regex | |
| `--skip-auth-strip-headers` | bool | strips `X-Forwarded-*` style authentication headers & `Authorization` header if they would be set by oauth2-proxy | true |
| `--skip-jwt-bearer-tokens` | bool | will skip requests that have verified JWT bearer tokens (the token must have [`aud`](https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields) that matches this client id or one of the extras from `extra-jwt-issuers`) | false |
| `--skip-oidc-discovery` | bool | bypass OIDC endpoint discovery. `--login-url`, `--redeem-url` and `--oidc-jwks-url` must be configured in this case | false |
| `--skip-provider-button` | bool | will skip sign-in-page to directly reach the next step: oauth/start | false |
| `--ssl-insecure-skip-verify` | bool | skip validation of certificates presented when using HTTPS providers | false |
| `--ssl-upstream-insecure-skip-verify` | bool | skip validation of certificates presented when using HTTPS upstreams | false |
| `--standard-logging` | bool | Log standard runtime information | true |
| `--standard-logging-format` | string | Template for standard log lines | see [Logging Configuration](#logging-configuration) |
| `--tls-cert-file` | string | path to certificate file | |
| `--tls-cipher-suite` | string \| list | Restricts TLS cipher suites used by server to those listed (e.g. TLS_RSA_WITH_RC4_128_SHA) (may be given multiple times). If not specified, the default Go safe cipher list is used. List of valid cipher suites can be found in the [crypto/tls documentation](https://pkg.go.dev/crypto/tls#pkg-constants). | |
| `--tls-key-file` | string | path to private key file | |
| `--tls-min-version` | string | minimum TLS version that is acceptable, either `"TLS1.2"` or `"TLS1.3"` | `"TLS1.2"` |
| `--upstream` | string \| list | the http url(s) of the upstream endpoint, file:// paths for static files or `static://<status_code>` for static response. Routing is based on the path | |
| `--upstream-timeout` | duration | maximum amount of time the server will wait for a response from the upstream | 30s |
| `--allowed-group` | string \| list | restrict logins to members of this group (may be given multiple times) | |
| `--allowed-role` | string \| list | restrict logins to users with this role (may be given multiple times). Only works with the keycloak-oidc provider. | |
| `--validate-url` | string | Access token validation endpoint | |
| `--version` | n/a | print version string | |
| `--whitelist-domain` | string \| list | allowed domains for redirection after authentication. Prefix domain with a `.` or a `*.` to allow subdomains (e.g. `.example.com`, `*.example.com`)&nbsp;\[[2](#footnote2)\] | |
| `--trusted-ip` | string \| list | list of IPs or CIDR ranges to allow to bypass authentication (may be given multiple times). When combined with `--reverse-proxy` and optionally `--real-client-ip-header` this will evaluate the trust of the IP stored in an HTTP header by a reverse proxy rather than the layer-3/4 remote address. WARNING: trusting IPs has inherent security flaws, especially when obtaining the IP address from an HTTP header (reverse-proxy mode). Use this option only if you understand the risks and how to manage them. | |

> ###### 1. Only these providers support `--cookie-refresh`: GitLab, Google and OIDC {#footnote1}
> ###### 2. When using the `whitelist-domain` option, any domain prefixed with a `.` or a `*.` will allow any subdomain of the specified domain as a valid redirect URL. By default, only empty ports are allowed. This translates to allowing the default port of the URLs protocol (80 for HTTP, 443 for HTTPS, etc.) since browsers omit them. To allow only a specific port, add it to the whitelisted domain: `example.com:8080`. To allow any port, use `*`: `example.com:*`. {#footnote2}

### Environment Variables

Every **command line argument** can be specified as an **environment variable** by prefixing it with `OAUTH2_PROXY_`, capitalising it, and replacing hyphens (`-`) with underscores (`_`).  

If the argument can be specified multiple times, the environment variable should be plural (trailing `S`). This is particularly useful for storing secrets outside a configuration file or the command line.  

:::tip 
Exemple:  
The `--cookie-secret` flag becomes the environement variable `OAUTH2_PROXY_COOKIE_SECRET`  
The `--email-domain` flag becomes the environement variable `OAUTH2_PROXY_EMAIL_DOMAINS`
:::

### Config File

Every **command line argument** can be specified in a **config file** by replacing hyphens (-) with underscores (\_).  
If the argument can be specified multiple times, the config option should be plural (trailing s).

:::tip 
Exemple:  
The `--cookie-secret` flag becomes the config option `cookie_secret`  
The `--email-domain` flag becomes the config option `email_domains`
:::

An example [oauth2-proxy.cfg](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/contrib/oauth2-proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `--config=/etc/oauth2-proxy.cfg`