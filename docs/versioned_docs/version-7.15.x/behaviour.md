---
id: behaviour
title: Behaviour
---

1. Authentication Requirement: All requests passing through the proxy to upstream applications require authentication, excluding default proxy endpoints.
    - Exception: If the request matches a skipped route (configured via `--skip-auth-route`):
        - Authentication is not enforced, but the proxy will opportunistically attempt to validate a session cookie (`--cookie-name`) or JWT (`--skip-jwt-bearer-tokens`) if present in the request.
        - Configured user info and authentication headers (e.g., `--pass-access-token`) are injected to upstream routes when validation succeeds.

2. Unauthenticated Requests: When authentication is missing but required, the user is redirected to the configured Identity Provider (IdP) login page by default.
    - Ajax Requests: If the request has `Accept: application/json` header:
        - Returns `401 Unauthorized`.
    - Invalid JWT Tokens: If `--skip-jwt-bearer-tokens` is set and the request includes an invalid JWT:
        - Redirects to the login page by default.
        - Returns `403 Forbidden` if `--bearer-token-login-fallback` is set to `false`.

3. Post-Authentication: After successful authentication with the IdP, OAuth tokens are stored in the configured session store (cookie or Redis), and a cookie is set.

4. Request Forwarding: The authenticated request is processed based on configuration:
    - Forwarded to the configured upstream application with added user info and authentication headers, or
    - Returns a valid status code for downstream processing by another proxy or load balancer (e.g., Nginx or Traefik).

---

Note: The proxy also provides a number of useful [endpoints](features/endpoints.md) for monitoring and management. 
