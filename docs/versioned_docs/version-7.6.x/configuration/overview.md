---
id: overview
title: Overview
---

`oauth2-proxy` can be configured via [command line options](#command-line-options), [environment variables](#environment-variables) or [config file](#config-file) (in decreasing order of precedence, i.e. command line options will overwrite environment variables and environment variables will overwrite configuration file settings).

## Generating a Cookie Secret

To generate a strong cookie secret use one of the below commands:

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs defaultValue="python">
  <TabItem value="python" label="Python">

  ```shell
  python -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
  ```
  
  </TabItem>
  <TabItem value="bash" label="Bash">

  ```shell
  dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d -- '\n' | tr -- '+/' '-_' ; echo
  ```
  
  </TabItem>
  <TabItem value="openssl" label="OpenSSL">

  ```shell
  openssl rand -base64 32 | tr -- '+/' '-_'
  ```

  </TabItem>
  <TabItem value="powershell" label="PowerShell">

  ```powershell
  # Add System.Web assembly to session, just in case
  Add-Type -AssemblyName System.Web
  [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Web.Security.Membership]::GeneratePassword(32,4))).Replace("+","-").Replace("/","_")
  ```

  </TabItem>
  <TabItem value="terraform" label="Terraform">

  ```hcl
  # Valid 32 Byte Base64 URL encoding set that will decode to 24 []byte AES-192 secret
  resource "random_password" "cookie_secret" {
    length           = 32
    override_special = "-_"
  }
  ```

  </TabItem>
</Tabs>

## Config File

Every command line argument can be specified in a config file by replacing hyphens (-) with underscores (\_). If the argument can be specified multiple times, the config option should be plural (trailing s).

An example [oauth2-proxy.cfg](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/contrib/oauth2-proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `--config=/etc/oauth2-proxy.cfg`

## Config Options

### Command Line Options

| Flag        | Description          |
| ----------- | -------------------- |
| `--config`  | path to config file  |
| `--version` | print version string |

### General Provider Options

Provider specific options can be found on their respective subpages.

| Flag / Config Field                                                                                 | Type           | Description                                                                                                                                                                                              | Default               |
| --------------------------------------------------------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| flag: `--acr-values`<br/>toml: `acr_values`                                                         | string         | optional, see [docs](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html#acrValues)                                                                                                          | `""`                  |
| flag: `--allowed-group`<br/>toml: `allowed_groups`                                                  | string \| list | Restrict login to members of a group or list of groups. Furthermore, if you aren't setting the `scope` and use `allowed_groups` with the generic OIDC provider the scope `groups` gets added implicitly. |                       |
| flag: `--approval-prompt`<br/>toml: `approval_prompt`                                               | string         | OAuth approval_prompt                                                                                                                                                                                    | `"force"`             |
| flag: `--backend-logout-url`<br/>toml: `backend_logout_url`                                         | string         | URL to perform backend logout, if you use `{id_token}` in the url it will be replaced by the actual `id_token` of the user session                                                                       |                       |
| flag: `--client-id`<br/>toml: `client_id`                                                           | string         | the OAuth Client ID, e.g. `"123456.apps.googleusercontent.com"`                                                                                                                                          |                       |
| flag: `--client-secret-file`<br/>toml: `client_secret_file`                                         | string         | the file with OAuth Client Secret                                                                                                                                                                        |                       |
| flag: `--client-secret`<br/>toml: `client_secret`                                                   | string         | the OAuth Client Secret                                                                                                                                                                                  |                       |
| flag: `--code-challenge-method`<br/>toml: `code_challenge_method`                                   | string         | use PKCE code challenges with the specified method. Either 'plain' or 'S256' (recommended)                                                                                                               |                       |
| flag: `--insecure-oidc-allow-unverified-email`<br/>toml: `insecure_oidc_allow_unverified_email`     | bool           | don't fail if an email address in an id_token is not verified                                                                                                                                            | false                 |
| flag: `--insecure-oidc-skip-issuer-verification`<br/>toml: `insecure_oidc_skip_issuer_verification` | bool           | allow the OIDC issuer URL to differ from the expected (currently required for Azure multi-tenant compatibility)                                                                                          | false                 |
| flag: `--insecure-oidc-skip-nonce`<br/>toml: `insecure_oidc_skip_nonce`                             | bool           | skip verifying the OIDC ID Token's nonce claim                                                                                                                                                           | true                  |
| flag: `--jwt-key-file`<br/>toml: `jwt_key_file`                                                     | string         | path to the private key file in PEM format used to sign the JWT so that you can say something like `--jwt-key-file=/etc/ssl/private/jwt_signing_key.pem`: required by login.gov                          |                       |
| flag: `--jwt-key`<br/>toml: `jwt_key`                                                               | string         | private key in PEM format used to sign JWT, so that you can say something like `--jwt-key="${OAUTH2_PROXY_JWT_KEY}"`: required by login.gov                                                              |                       |
| flag: `--login-url`<br/>toml: `login_url`                                                           | string         | Authentication endpoint                                                                                                                                                                                  |                       |
| flag: `--oidc-audience-claim`<br/>toml: `oidc_audience_claims`                                      | string         | which OIDC claim contains the audience                                                                                                                                                                   | `"aud"`               |
| flag: `--oidc-email-claim`<br/>toml: `oidc_email_claim`                                             | string         | which OIDC claim contains the user's email                                                                                                                                                               | `"email"`             |
| flag: `--oidc-extra-audience`<br/>toml: `oidc_extra_audiences`                                      | string \| list | additional audiences which are allowed to pass verification                                                                                                                                              | `"[]"`                |
| flag: `--oidc-groups-claim`<br/>toml: `oidc_groups_claim`                                           | string         | which OIDC claim contains the user groups                                                                                                                                                                | `"groups"`            |
| flag: `--oidc-issuer-url`<br/>toml: `oidc_issuer_url`                                               | string         | the OpenID Connect issuer URL, e.g. `"https://accounts.google.com"`                                                                                                                                      |                       |
| flag: `--oidc-jwks-url`<br/>toml: `oidc_jwks_url`                                                   | string         | OIDC JWKS URI for token verification; required if OIDC discovery is disabled                                                                                                                             |                       |
| flag: `--profile-url`<br/>toml: `profile_url`                                                       | string         | Profile access endpoint                                                                                                                                                                                  |                       |
| flag: `--prompt`<br/>toml: `prompt`                                                                 | string         | [OIDC prompt](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest); if present, `approval-prompt` is ignored                                                                               | `""`                  |
| flag: `--provider-ca-file`<br/>toml: `provider_ca_files`                                            | string \| list | Paths to CA certificates that should be used when connecting to the provider. If not specified, the default Go trust sources are used instead.                                                           |
| flag: `--provider-display-name`<br/>toml: `provider_display_name`                                   | string         | Override the provider's name with the given string; used for the sign-in page                                                                                                                            | (depends on provider) |
| flag: `--provider`<br/>toml: `provider`                                                             | string         | OAuth provider                                                                                                                                                                                           | google                |
| flag: `--pubjwk-url`<br/>toml: `pubjwk_url`                                                         | string         | JWK pubkey access endpoint: required by login.gov                                                                                                                                                        |                       |
| flag: `--redeem-url`<br/>toml: `redeem_url`                                                         | string         | Token redemption endpoint                                                                                                                                                                                |                       |
| flag: `--scope`<br/>toml:`scope`                                                                    | string         | OAuth scope specification. Every provider has a default list of scopes which will be used in case no scope is configured.                                                                                |                       |
| flag: `--skip-claims-from-profile-url`<br/>toml: `skip_claims_from_profile_url`                     | bool           | skip request to Profile URL for resolving claims not present in id_token                                                                                                                                 | false                 |
| flag: `--skip-oidc-discovery`<br/>toml: `skip_oidc_discovery`                                       | bool           | bypass OIDC endpoint discovery. `--login-url`, `--redeem-url` and `--oidc-jwks-url` must be configured in this case                                                                                      | false                 |
| flag: `--use-system-trust-store`<br/>toml: `use_system_trust_store`                                 | bool           | Determines if `provider-ca-file` files and the system trust store are used. If set to true, your custom CA files and the system trust store are used otherwise only your custom CA files.                | false                 |
| flag: `--validate-url`<br/>toml: `validate_url`                                                     | string         | Access token validation endpoint                                                                                                                                                                         |                       |

### Cookie Options

| Flag / Config Field                                                  | Type           | Description                                                                                                                                                                                                                        | Default           |
| -------------------------------------------------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| flag: `--cookie-csrf-expire`<br/>toml: `cookie_csrf_expire`          | duration       | expire timeframe for CSRF cookie                                                                                                                                                                                                   | 15m               |
| flag: `--cookie-csrf-per-request`<br/>toml:`cookie_csrf_per_request` | bool           | Enable having different CSRF cookies per request, making it possible to have parallel requests.                                                                                                                                    | false             |
| flag: `--cookie-domain`<br/>toml: `cookie_domains`                   | string \| list | Optional cookie domains to force cookies to (e.g. `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match).                                           |                   |
| flag: `--cookie-expire`<br/>toml: `cookie_expire`                    | duration       | expire timeframe for cookie. If set to 0, cookie becomes a session-cookie which will expire when the browser is closed.                                                                                                            | 168h0m0s          |
| flag: `--cookie-httponly`<br/>toml: `cookie_httponly`                | bool           | set HttpOnly cookie flag                                                                                                                                                                                                           | true              |
| flag: `--cookie-name`<br/>toml: `cookie_name`                        | string         | the name of the cookie that the oauth_proxy creates. Should be changed to use a [cookie prefix](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes) (`__Host-` or `__Secure-`) if `--cookie-secure` is set. | `"_oauth2_proxy"` |
| flag: `--cookie-path`<br/>toml: `cookie_path`                        | string         | an optional cookie path to force cookies to (e.g. `/poc/`)                                                                                                                                                                         | `"/"`             |
| flag: `--cookie-refresh`<br/>toml: `cookie_refresh`                  | duration       | refresh the cookie after this duration; `0` to disable; not supported by all providers&nbsp;[^1]                                                                                                                                   |                   |
| flag: `--cookie-samesite`<br/>toml: `cookie_samesite`                | string         | set SameSite cookie attribute (`"lax"`, `"strict"`, `"none"`, or `""`).                                                                                                                                                            | `""`              |
| flag: `--cookie-secret`<br/>toml: `cookie_secret`                    | string         | the seed string for secure cookies (optionally base64 encoded)                                                                                                                                                                     |                   |
| flag: `--cookie-secure`<br/>toml: `cookie_secure`                    | bool           | set [secure (HTTPS only) cookie flag](https://owasp.org/www-community/controls/SecureFlag)                                                                                                                                         | true              |

[^1]: The following providers support `--cookie-refresh`: ADFS, Azure, GitLab, Google, Keycloak and all other Identity Providers which support the full [OIDC specification](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens)

### Header Options

| Flag / Config Field                                                       | Type   | Description                                                                                                                                                                                                                                                      | Default |
| ------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| flag: `--basic-auth-password`<br/>toml: `basic_auth_password`             | string | the password to set when passing the HTTP Basic Auth header                                                                                                                                                                                                      |         |
| flag: `--set-xauthrequest`<br/>toml: `set_xauthrequest`                   | bool   | set X-Auth-Request-User, X-Auth-Request-Groups, X-Auth-Request-Email and X-Auth-Request-Preferred-Username response headers (useful in Nginx auth_request mode). When used with `--pass-access-token`, X-Auth-Request-Access-Token is added to response headers. | false   |
| flag: `--set-authorization-header`<br/>toml: `set_authorization_header`   | bool   | set Authorization Bearer response header (useful in Nginx auth_request mode)                                                                                                                                                                                     | false   |
| flag: `--set-basic-auth`<br/>toml: `set_basic_auth`                       | bool   | set HTTP Basic Auth information in response (useful in Nginx auth_request mode)                                                                                                                                                                                  | false   |
| flag: `--skip-auth-strip-headers`<br/>toml: `skip_auth_strip_headers`     | bool   | strips `X-Forwarded-*` style authentication headers & `Authorization` header if they would be set by oauth2-proxy                                                                                                                                                | true    |
| flag: `--pass-access-token`<br/>toml: `pass_access_token`                 | bool   | pass OAuth access_token to upstream via X-Forwarded-Access-Token header. When used with `--set-xauthrequest` this adds the X-Auth-Request-Access-Token header to the response                                                                                    | false   |
| flag: `--pass-authorization-header`<br/>toml: `pass_authorization_header` | bool   | pass OIDC IDToken to upstream via Authorization Bearer header                                                                                                                                                                                                    | false   |
| flag: `--pass-basic-auth`<br/>toml: `pass_basic_auth`                     | bool   | pass HTTP Basic Auth, X-Forwarded-User, X-Forwarded-Email and X-Forwarded-Preferred-Username information to upstream                                                                                                                                             | true    |
| flag: `--prefer-email-to-user`<br/>toml: `prefer_email_to_user`           | bool   | Prefer to use the Email address as the Username when passing information to upstream. Will only use Username if Email is unavailable, e.g. htaccess authentication. Used in conjunction with `--pass-basic-auth` and `--pass-user-headers`                       | false   |
| flag: `--pass-user-headers`<br/>toml: `pass_user_headers`                 | bool   | pass X-Forwarded-User, X-Forwarded-Groups, X-Forwarded-Email and X-Forwarded-Preferred-Username information to upstream                                                                                                                                          | true    |

### Logging Options

| Flag / Config Field                                                   | Type   | Description                                                                  | Default                                             |
| --------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------- | --------------------------------------------------- |
| flag: `--auth-logging-format`<br/>toml: `auth_logging_format`         | string | Template for authentication log lines                                        | see [Logging Configuration](#logging-configuration) |
| flag: `--auth-logging`<br/>toml: `auth_logging`                       | bool   | Log authentication attempts                                                  | true                                                |
| flag: `--errors-to-info-log`<br/>toml: `errors_to_info_log`           | bool   | redirects error-level logging to default log channel instead of stderr       | false                                               |
| flag: `--exclude-logging-path`<br/>toml: `exclude_logging_paths`      | string | comma separated list of paths to exclude from logging, e.g. `"/ping,/path2"` | `""` (no paths excluded)                            |
| flag: `--logging-compress`<br/>toml: `logging_compress`               | bool   | Should rotated log files be compressed using gzip                            | false                                               |
| flag: `--logging-filename`<br/>toml: `logging_filename`               | string | File to log requests to, empty for `stdout`                                  | `""` (stdout)                                       |
| flag: `--logging-local-time`<br/>toml: `logging_local_time`           | bool   | Use local time in log files and backup filenames instead of UTC              | true (local time)                                   |
| flag: `--logging-max-age`<br/>toml: `logging_max_age`                 | int    | Maximum number of days to retain old log files                               | 7                                                   |
| flag: `--logging-max-backups`<br/>toml: `logging_max_backups`         | int    | Maximum number of old log files to retain; 0 to disable                      | 0                                                   |
| flag: `--logging-max-size`<br/>toml: `logging_max_size`               | int    | Maximum size in megabytes of the log file before rotation                    | 100                                                 |
| flag: `--request-id-header`<br/>toml: `request_id_header`             | string | Request header to use as the request ID in logging                           | X-Request-Id                                        |
| flag: `--request-logging-format`<br/>toml: `request_logging_format`   | string | Template for request log lines                                               | see [Logging Configuration](#logging-configuration) |
| flag: `--request-logging`<br/>toml: `request_logging`                 | bool   | Log requests                                                                 | true                                                |
| flag: `--silence-ping-logging`<br/>toml: `silence_ping_logging`       | bool   | disable logging of requests to ping & ready endpoints                        | false                                               |
| flag: `--standard-logging-format`<br/>toml: `standard_logging_format` | string | Template for standard log lines                                              | see [Logging Configuration](#logging-configuration) |
| flag: `--standard-logging`<br/>toml: `standard_logging`               | bool   | Log standard runtime information                                             | true                                                |

### Page Template Options

| Flag / Config Field                                               | Type   | Description                                                                                                                 | Default |
| ----------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------- | ------- |
| flag: `--banner`<br/>toml: `banner`                               | string | custom (html) banner string. Use `"-"` to disable default banner.                                                           |         |
| flag: `--custom-sign-in-logo`<br/>toml: `custom_sign_in_logo`     | string | path or a URL to an custom image for the sign_in page logo. Use `"-"` to disable default logo.                              |
| flag: `--custom-templates-dir`<br/>toml: `custom_templates_dir`   | string | path to custom html templates                                                                                               |         |
| flag: `--display-htpasswd-form`<br/>toml: `display_htpasswd_form` | bool   | display username / password login form if an htpasswd file is provided                                                      | true    |
| flag: `--footer`<br/>toml: `footer`                               | string | custom (html) footer string. Use `"-"` to disable default footer.                                                           |         |
| flag: `--show-debug-on-error`<br/>toml: `show_debug_on_error`     | bool   | show detailed error information on error pages (WARNING: this may contain sensitive information - do not use in production) | false   |

### Probe Options

| Flag / Config Field                                     | Type   | Description                                                | Default                       |
| ------------------------------------------------------- | ------ | ---------------------------------------------------------- | ----------------------------- |
| flag: `--ping-path`<br/>toml: `ping_path`               | string | the ping endpoint that can be used for basic health checks | `"/ping"`                     |
| flag: `--ping-user-agent`<br/>toml: `ping_user_agent`   | string | a User-Agent that can be used for basic health checks      | `""` (don't check user agent) |
| flag: `--ready-path`<br/>toml: `ready_path`             | string | the ready endpoint that can be used for deep health checks | `"/ready"`                    |
| flag: `--gcp-healthchecks`<br/>toml: `gcp_healthchecks` | bool   | Enable GCP/GKE healthcheck endpoints (deprecated)          | false                         |

### Proxy Options

| Flag / Config Field                                                       | Type           | Description                                                                                                                                                                                                                   | Default     |
| ------------------------------------------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| flag: `--allow-query-semicolons`<br/>toml: `allow_query_semicolons`       | bool           | allow the use of semicolons in query args ([required for some legacy applications](https://github.com/golang/go/issues/25192))                                                                                                | `false`     |
| flag: `--api-route`<br/>toml: `api_routes`                                | string \| list | return HTTP 401 instead of redirecting to authentication server if token is not valid. Format: path_regex                                                                                                                     |             |
| flag: `--authenticated-emails-file`<br/>toml: `authenticated_emails_file` | string         | authenticate against emails via file (one per line)                                                                                                                                                                           |             |
| flag: `--email-domain`<br/>toml: `email_domains`                          | string \| list | authenticate emails with the specified domain (may be given multiple times). Use `*` to authenticate any email                                                                                                                |             |
| flag: `--encode-state`<br/>toml: `encode_state`                           | bool           | encode the state parameter as UrlEncodedBase64                                                                                                                                                                                | false       |
| flag: `--extra-jwt-issuers`<br/>toml: `extra_jwt_issuers`                 | string         | if `--skip-jwt-bearer-tokens` is set, a list of extra JWT `issuer=audience` (see a token's `iss`, `aud` fields) pairs (where the issuer URL has a `.well-known/openid-configuration` or a `.well-known/jwks.json`)            |             |
| flag: `--force-https`<br/>toml: `force_https`                             | bool           | enforce https redirect                                                                                                                                                                                                        | `false`     |
| flag: `--force-json-errors`<br/>toml: `force_json_errors`                 | bool           | force JSON errors instead of HTTP error pages or redirects                                                                                                                                                                    | `false`     |
| flag: `--htpasswd-file`<br/>toml: `htpasswd_file`                         | string         | additionally authenticate against a htpasswd file. Entries must be created with `htpasswd -B` for bcrypt encryption                                                                                                           |             |
| flag: `--htpasswd-user-group`<br/>toml: `htpasswd_user_groups`            | string \| list | the groups to be set on sessions for htpasswd users                                                                                                                                                                           |             |
| flag: `--proxy-prefix`<br/>toml: `proxy_prefix`                           | string         | the url root path that this proxy should be nested under (e.g. /`<oauth2>/sign_in`)                                                                                                                                           | `"/oauth2"` |
| flag: `--real-client-ip-header`<br/>toml: `real_client_ip_header`         | string         | Header used to determine the real IP of the client, requires `--reverse-proxy` to be set (one of: X-Forwarded-For, X-Real-IP, or X-ProxyUser-IP)                                                                              | X-Real-IP   |
| flag: `--redirect-url`<br/>toml: `redirect_url`                           | string         | the OAuth Redirect URL, e.g. `"https://internalapp.yourcompany.com/oauth2/callback"`                                                                                                                                          |             |
| flag: `--relative-redirect-url`<br/>toml: `relative_redirect_url`         | bool           | allow relative OAuth Redirect URL.`                                                                                                                                                                                           | false       |
| flag: `--reverse-proxy`<br/>toml: `reverse_proxy`                         | bool           | are we running behind a reverse proxy, controls whether headers like X-Real-IP are accepted and allows X-Forwarded-\{Proto,Host,Uri\} headers to be used on redirect selection                                                | false       |
| flag: `--signature-key`<br/>toml: `signature_key`                         | string         | GAP-Signature request signature key (algorithm:secretkey)                                                                                                                                                                     |             |
| flag: `--skip-auth-preflight`<br/>toml: `skip_auth_preflight`             | bool           | will skip authentication for OPTIONS requests                                                                                                                                                                                 | false       |
| flag: `--skip-auth-regex`<br/>toml: `skip_auth_regex`                     | string \| list | (DEPRECATED for `--skip-auth-route`) bypass authentication for requests paths that match (may be given multiple times)                                                                                                        |             |
| flag: `--skip-auth-route`<br/>toml: `skip_auth_routes`                    | string \| list | bypass authentication for requests that match the method & path. Format: method=path_regex OR method!=path_regex. For all methods: path_regex OR !=path_regex                                                                 |             |
| flag: `--skip-jwt-bearer-tokens`<br/>toml: `skip_jwt_bearer_tokens`       | bool           | will skip requests that have verified JWT bearer tokens (the token must have [`aud`](https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields) that matches this client id or one of the extras from `extra-jwt-issuers`) | false       |
| flag: `--skip-provider-button`<br/>toml: `skip_provider_button`           | bool           | will skip sign-in-page to directly reach the next step: oauth/start                                                                                                                                                           | false       |
| flag: `--ssl-insecure-skip-verify`<br/>toml: `ssl_insecure_skip_verify`   | bool           | skip validation of certificates presented when using HTTPS providers                                                                                                                                                          | false       |
| flag: `--trusted-ip`<br/>toml: `trusted_ips`                              | bool           | encode the state parameter as UrlEncodedBase64                                                                                                                                                                                | false       |
| flag: `--whitelist-domain`<br/>toml: `whitelist_domains`                  | string \| list | allowed domains for redirection after authentication. Prefix domain with a `.` or a `*.` to allow subdomains (e.g. `.example.com`, `*.example.com`)&nbsp;[^2]                                                                 |             |

[^2]: When using the `whitelist-domain` option, any domain prefixed with a `.` or a `*.` will allow any subdomain of the specified domain as a valid redirect URL. By default, only empty ports are allowed. This translates to allowing the default port of the URL's protocol (80 for HTTP, 443 for HTTPS, etc.) since browsers omit them. To allow only a specific port, add it to the whitelisted domain: `example.com:8080`. To allow any port, use `*`: `example.com:*`.

### Server Options

| Flag / Config Field                                                 | Type           | Description                                                                                                                                                                                                                                                                                                   | Default            |
| ------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| flag: `--http-address`<br/>toml: `http_address`                     | string         | `[http://]<addr>:<port>` or `unix://<path>` to listen on for HTTP clients. Square brackets are required for ipv6 address, e.g. `http://[::1]:4180`                                                                                                                                                            | `"127.0.0.1:4180"` |
| flag: `--https-address`<br/>toml: `https_address`                   | string         | `[https://]<addr>:<port>` to listen on for HTTPS clients. Square brackets are required for ipv6 address, e.g. `https://[::1]:443`                                                                                                                                                                             | `":443"`           |
| flag: `--metrics-address`<br/>toml: `metrics_address`               | string         | the address prometheus metrics will be scraped from                                                                                                                                                                                                                                                           | `""`               |
| flag: `--metrics-secure-address`<br/>toml: `metrics_secure_address` | string         | the address prometheus metrics will be scraped from if using HTTPS                                                                                                                                                                                                                                            | `""`               |
| flag: `--metrics-tls-cert-file`<br/>toml: `metrics_tls_cert_file`   | string         | path to certificate file for secure metrics server                                                                                                                                                                                                                                                            | `""`               |
| flag: `--metrics-tls-key-file`<br/>toml: `metrics_tls_key_file`     | string         | path to private key file for secure metrics server                                                                                                                                                                                                                                                            | `""`               |
| flag: `--tls-cert-file`<br/>toml: `tls_cert_file`                   | string         | path to certificate file                                                                                                                                                                                                                                                                                      |                    |
| flag: `--tls-key-file`<br/>toml: `tls_key_file`                     | string         | path to private key file                                                                                                                                                                                                                                                                                      |                    |
| flag: `--tls-cipher-suite`<br/>toml: `tls_cipher_suites`            | string \| list | Restricts TLS cipher suites used by server to those listed (e.g. TLS_RSA_WITH_RC4_128_SHA) (may be given multiple times). If not specified, the default Go safe cipher list is used. List of valid cipher suites can be found in the [crypto/tls documentation](https://pkg.go.dev/crypto/tls#pkg-constants). |                    |
| flag: `--tls-min-version`<br/>toml: `tls_min_version`               | string         | minimum TLS version that is acceptable, either `"TLS1.2"` or `"TLS1.3"`                                                                                                                                                                                                                                       | `"TLS1.2"`         |

### Session Options
| Flag / Config Field                                                                 | Type           | Description                                                                                                                                                                                                                                                                                                                                                                                                   | Default |
| ----------------------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| flag: `--session-cookie-minimal`<br/>toml: `session_cookie_minimal`                 | bool           | strip OAuth tokens from cookie session stores if they aren't needed (cookie session store only)                                                                                                                                                                                                                                                                                                               | false   |
| flag: `--session-store-type`<br/>toml: `session_store_type`                         | string         | [Session data storage backend](sessions.md); redis or cookie                                                                                                                                                                                                                                                                                                                                                  | cookie  |
| flag: `--redis-cluster-connection-urls`<br/>toml: `redis_cluster_connection_urls`   | string \| list | List of Redis cluster connection URLs (e.g. `redis://HOST[:PORT]`). Used in conjunction with `--redis-use-cluster`                                                                                                                                                                                                                                                                                            |         |
| flag: `--redis-connection-url`<br/>toml: `redis_connection_url`                     | string         | URL of redis server for redis session storage (e.g. `redis://HOST[:PORT]`)                                                                                                                                                                                                                                                                                                                                    |         |
| flag: `--redis-insecure-skip-tls-verify`<br/>toml: `redis_insecure_skip_tls_verify` | bool           | skip TLS verification when connecting to Redis                                                                                                                                                                                                                                                                                                                                                                | false   |
| flag: `--redis-password`<br/>toml: `redis_password`                                 | string         | Redis password. Applicable for all Redis configurations. Will override any password set in `--redis-connection-url`                                                                                                                                                                                                                                                                                           |         |
| flag: `--redis-sentinel-password`<br/>toml: `redis_sentinel_password`               | string         | Redis sentinel password. Used only for sentinel connection; any redis node passwords need to use `--redis-password`                                                                                                                                                                                                                                                                                           |         |
| flag: `--redis-sentinel-master-name`<br/>toml: `redis_sentinel_master_name`         | string         | Redis sentinel master name. Used in conjunction with `--redis-use-sentinel`                                                                                                                                                                                                                                                                                                                                   |         |
| flag: `--redis-sentinel-connection-urls`<br/>toml: `redis_sentinel_connection_urls` | string \| list | List of Redis sentinel connection URLs (e.g. `redis://HOST[:PORT]`). Used in conjunction with `--redis-use-sentinel`                                                                                                                                                                                                                                                                                          |         |
| flag: `--redis-use-cluster`<br/>toml: `redis_use_cluster`                           | bool           | Connect to redis cluster. Must set `--redis-cluster-connection-urls` to use this feature                                                                                                                                                                                                                                                                                                                      | false   |
| flag: `--redis-use-sentinel`<br/>toml: `redis_use_sentinel`                         | bool           | Connect to redis via sentinels. Must set `--redis-sentinel-master-name` and `--redis-sentinel-connection-urls` to use this feature                                                                                                                                                                                                                                                                            | false   |
| flag: `--redis-connection-idle-timeout`<br/>toml: `redis_connection_idle_timeout`   | int            | Redis connection idle timeout seconds. If Redis [timeout](https://redis.io/docs/reference/clients/#client-timeouts) option is set to non-zero, the `--redis-connection-idle-timeout` must be less than Redis timeout option. Example: if either redis.conf includes `timeout 15` or using `CONFIG SET timeout 15` the `--redis-connection-idle-timeout` must be at least `--redis-connection-idle-timeout=14` | 0       |

### Upstream Options

| Flag / Config Field                                                                       | Type           | Description                                                                                                                                            | Default |
| ----------------------------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| flag: `--flush-interval`<br/>toml: `flush_interval`                                       | duration       | period between flushing response buffers when streaming responses                                                                                      | `"1s"`  |
| flag: `--pass-host-header`<br/>toml: `pass_host_header`                                   | bool           | pass the request Host Header to upstream                                                                                                               | true    |
| flag: `--proxy-websockets`<br/>toml: `proxy_websockets`                                   | bool           | enables WebSocket proxying                                                                                                                             | true    |
| flag: `--ssl-upstream-insecure-skip-verify`<br/>toml: `ssl_upstream_insecure_skip_verify` | bool           | skip validation of certificates presented when using HTTPS upstreams                                                                                   | false   |
| flag: `--upstream-timeout`<br/>toml: `upstream_timeout`                                   | duration       | maximum amount of time the server will wait for a response from the upstream                                                                           | 30s     |
| flag: `--upstream`<br/>toml: `upstreams`                                                  | string \| list | the http url(s) of the upstream endpoint, file:// paths for static files or `static://<status_code>` for static response. Routing is based on the path |         |

## Upstreams Configuration

`oauth2-proxy` supports having multiple upstreams, and has the option to pass requests on to HTTP(S) servers, unix socket or serve static files from the file system.

HTTP and HTTPS upstreams are configured by providing a URL such as `http://127.0.0.1:8080/` for the upstream parameter. . This will forward all authenticated requests to the upstream server. If you instead provide `http://127.0.0.1:8080/some/path/` then it will only be requests that start with `/some/path/` which are forwarded to the upstream.

Unix socket upstreams are configured as `unix:///path/to/unix.sock`.

Static file paths are configured as a file:// URL. `file:///var/www/static/` will serve the files from that directory at `http://[oauth2-proxy url]/var/www/static/`, which may not be what you want. You can provide the path to where the files should be available by adding a fragment to the configured URL. The value of the fragment will then be used to specify which path the files are available at, e.g. `file:///var/www/static/#/static/` will make `/var/www/static/` available at `http://[oauth2-proxy url]/static/`.

Multiple upstreams can either be configured by supplying a comma separated list to the `--upstream` parameter, supplying the parameter multiple times or providing a list in the [config file](#config-file). When multiple upstreams are used routing to them will be based on the path they are set up with.

## Environment variables

Every command line argument can be specified as an environment variable by
prefixing it with `OAUTH2_PROXY_`, capitalising it, and replacing hyphens (`-`)
with underscores (`_`). If the argument can be specified multiple times, the
environment variable should be plural (trailing `S`).

This is particularly useful for storing secrets outside a configuration file
or the command line.

For example, the `--cookie-secret` flag becomes `OAUTH2_PROXY_COOKIE_SECRET`.
If a flag has the type `string | list` like the `--email-domain` flag it is
available as an environment variable in plural form e.g. `OAUTH2_PROXY_EMAIL_DOMAINS`

Values for type `string | list` usually have a plural environment variable name
and need to be seperated by `,` e.g.
`OAUTH2_PROXY_SKIP_AUTH_ROUTES="GET=^/api/status,POST=^/api/saved_objects/_import"`

Please check the type for each [config option](#config-options) first.

## Logging Configuration

By default, OAuth2 Proxy logs all output to stdout. Logging can be configured to output to a rotating log file using the `--logging-filename` command.

If logging to a file you can also configure the maximum file size (`--logging-max-size`), age (`--logging-max-age`), max backup logs (`--logging-max-backups`), and if backup logs should be compressed (`--logging-compress`).

There are three different types of logging: standard, authentication, and HTTP requests. These can each be enabled or disabled with `--standard-logging`, `--auth-logging`, and `--request-logging`.

Each type of logging has its own configurable format and variables. By default, these formats are similar to the Apache Combined Log.

Logging of requests to the `/ping` endpoint (or using `--ping-user-agent`) and the `/ready` endpoint can be disabled with `--silence-ping-logging` reducing log volume.

## Auth Log Format
Authentication logs are logs which are guaranteed to contain a username or email address of a user attempting to authenticate. These logs are output by default in the below format:

```
<REMOTE_ADDRESS> - <REQUEST ID> - <user@domain.com> [2015/03/19 17:20:19] [<STATUS>] <MESSAGE>
```

The status block will contain one of the below strings:

- `AuthSuccess` If a user has authenticated successfully by any method
- `AuthFailure` If the user failed to authenticate explicitly
- `AuthError` If there was an unexpected error during authentication

If you require a different format than that, you can configure it with the `--auth-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}
```

Available variables for auth logging:

| Variable      | Example                              | Description                                                                                              |
| ------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Client        | 74.125.224.72                        | The client/remote IP address. Will use the X-Real-IP header it if exists & reverse-proxy is set to true. |
| Host          | domain.com                           | The value of the Host header.                                                                            |
| Message       | Authenticated via OAuth2             | The details of the auth attempt.                                                                         |
| Protocol      | HTTP/1.0                             | The request protocol.                                                                                    |
| RequestID     | 00010203-0405-4607-8809-0a0b0c0d0e0f | The request ID pulled from the `--request-id-header`. Random UUID if empty                               |
| RequestMethod | GET                                  | The request method.                                                                                      |
| Timestamp     | 2015/03/19 17:20:19                  | The date and time of the logging event.                                                                  |
| UserAgent     | -                                    | The full user agent as reported by the requesting client.                                                |
| Username      | username@email.com                   | The email or username of the auth request.                                                               |
| Status        | AuthSuccess                          | The status of the auth request. See above for details.                                                   |

## Request Log Format
HTTP request logs will output by default in the below format:

```
<REMOTE_ADDRESS> - <REQUEST ID> - <user@domain.com> [2015/03/19 17:20:19] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

If you require a different format than that, you can configure it with the `--request-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}
```

Available variables for request logging:

| Variable        | Example                              | Description                                                                                              |
| --------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Client          | 74.125.224.72                        | The client/remote IP address. Will use the X-Real-IP header it if exists & reverse-proxy is set to true. |
| Host            | domain.com                           | The value of the Host header.                                                                            |
| Protocol        | HTTP/1.0                             | The request protocol.                                                                                    |
| RequestDuration | 0.001                                | The time in seconds that a request took to process.                                                      |
| RequestID       | 00010203-0405-4607-8809-0a0b0c0d0e0f | The request ID pulled from the `--request-id-header`. Random UUID if empty                               |
| RequestMethod   | GET                                  | The request method.                                                                                      |
| RequestURI      | "/oauth2/auth"                       | The URI path of the request.                                                                             |
| ResponseSize    | 12                                   | The size in bytes of the response.                                                                       |
| StatusCode      | 200                                  | The HTTP status code of the response.                                                                    |
| Timestamp       | 2015/03/19 17:20:19                  | The date and time of the logging event.                                                                  |
| Upstream        | -                                    | The upstream data of the HTTP request.                                                                   |
| UserAgent       | -                                    | The full user agent as reported by the requesting client.                                                |
| Username        | username@email.com                   | The email or username of the auth request.                                                               |

## Standard Log Format
All other logging that is not covered by the above two types of logging will be output in this standard logging format. This includes configuration information at startup and errors that occur outside of a session. The default format is below:

```
[2015/03/19 17:20:19] [main.go:40] <MESSAGE>
```

If you require a different format than that, you can configure it with the `--standard-logging-format` flag. The default format is configured as follows:

```
[{{.Timestamp}}] [{{.File}}] {{.Message}}
```

Available variables for standard logging:

| Variable  | Example                           | Description                                        |
| --------- | --------------------------------- | -------------------------------------------------- |
| Timestamp | 2015/03/19 17:20:19               | The date and time of the logging event.            |
| File      | main.go:40                        | The file and line number of the logging statement. |
| Message   | HTTP: listening on 127.0.0.1:4180 | The details of the log statement.                  |
