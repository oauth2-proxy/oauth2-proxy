---
id: endpoints
title: Endpoints
---

OAuth2 Proxy responds directly to the following endpoints. All other endpoints will be proxied upstream when authenticated. The `/oauth2` prefix can be changed with the `--proxy-prefix` config variable.

- / - the proxy endpoint provides authentication and returns the appropriate 40x error if not authenticated or authorized then passes the request upstream.
- /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
- /ping - returns a 200 OK response, which is intended for use with health checks
- /ready - returns a 200 OK response if all the underlying connections (e.g., Redis store) are connected
- /metrics - Metrics endpoint for Prometheus to scrape, serve on the address specified by `--metrics-address`, disabled by default
- /oauth2/sign_in - the login page, which also doubles as a sign-out page (it clears cookies)
- /oauth2/sign_out - this URL is used to clear the session cookie
- /oauth2/start - a URL that will redirect to start the OAuth cycle
- /oauth2/callback - the URL used at the end of the OAuth cycle. The oauth app will be configured with this as the callback url.
- /oauth2/userinfo - the URL is used to return user's email from the session in JSON format.
- /oauth2/auth - only returns a 202 Accepted response or a 401 Unauthorized response; for use with the [Nginx `auth_request` directive](../configuration/integrations/nginx)
- /oauth2/static/\* - stylesheets and other dependencies used in the sign_in and error pages

### Sign out

To sign the user out, redirect them to `/oauth2/sign_out`. This endpoint only removes oauth2-proxy's own cookies, i.e. the user is still logged in with the authentication provider and may automatically re-login when accessing the application again. You will also need to redirect the user to the authentication provider's sign-out page afterward using the `rd` query parameter, i.e. redirect the user to something like (notice the url-encoding!):

```
/oauth2/sign_out?rd=https%3A%2F%2Fmy-oidc-provider.example.com%2Fsign_out_page
```

Alternatively, include the redirect URL in the `X-Auth-Request-Redirect` header:

```
GET /oauth2/sign_out HTTP/1.1
X-Auth-Request-Redirect: https://my-oidc-provider/sign_out_page
...
```

(The "sign_out_page" should be the [`end_session_endpoint`](https://openid.net/specs/openid-connect-session-1_0.html#rfc.section.2.1) from [the metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) if your OIDC provider supports Session Management and Discovery.)

BEWARE that the domain you want to redirect to (`my-oidc-provider.example.com` in the example) must be added to the [`--whitelist-domain`](../configuration/overview) configuration option otherwise the redirect will be ignored. Make sure to include the actual domain and port (if needed) and not the URL (e.g "localhost:8081" instead of "http://localhost:8081").

### Auth

This endpoint is used for Nginx subrequest authentication. It returns the following status codes based on the request state:
* **202 Accepted:** The user is authenticated and passes all authorization logic checks.
* **403 Forbidden:** The user is authenticated but fails the configured logic checks (e.g., wrong group or email domain).
* **401 Unauthorized:** The user is unable to authenticate (missing or invalid session).

It can be configured using the following query parameters:
- `allowed_groups`: comma separated list of allowed groups
- `allowed_email_domains`: comma separated list of allowed email domains
- `allowed_emails`: comma separated list of allowed emails
- `allowed_users`: comma separated list of allowed users
- `require_all_matches`: (boolean, default: `true`) Determines if all defined constraints must pass.
- `constraints_required`: (boolean, default: `false`) Determines if the request is denied when no constraints are present.

**Logic Behavior:**
* **Default (AND Logic):** If multiple constraints are provided (e.g., `allowed_users` AND `allowed_groups`), the user must satisfy **ALL** of them.
* **OR Logic:** If `require_all_matches=false` is set, the user must satisfy **AT LEAST ONE** of the provided constraints.
* **Empty State:** If no constraints are provided, the request is allowed by default. Set `constraints_required=true` to deny requests that do not match at least one specific restriction.

### Proxy (/)

This endpoint proxies the request to the upstream service. It returns the following status codes based on the request state:
* **Upstream Response:** The user is authenticated and passes all authorization logic checks.
* **403 Forbidden:** The user is authenticated but fails the configured logic checks.
* **401 Unauthorized:** The user is unable to authenticate.

It can be configured using the following query parameters:
- `allowed_groups`: comma separated list of allowed groups
- `allowed_email_domains`: comma separated list of allowed email domains
- `allowed_emails`: comma separated list of allowed emails
- `allowed_users`: comma separated list of allowed users
- `require_all_matches`: (boolean, default: `true`) Determines if all defined constraints must pass.
- `constraints_required`: (boolean, default: `false`) Determines if the request is denied when no constraints are present.

**Logic Behavior:**
* **Default (AND Logic):** If multiple constraints are provided (e.g., `allowed_users` AND `allowed_groups`), the user must satisfy **ALL** of them.
* **OR Logic:** If `require_all_matches=false` is set, the user must satisfy **AT LEAST ONE** of the provided constraints.
* **Empty State:** If no constraints are provided, the request is allowed by default. Set `constraints_required=true` to deny requests that do not match at least one specific restriction.
