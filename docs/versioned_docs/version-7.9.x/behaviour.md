 ---
id: behaviour
title: Behaviour
---


1. Any request passing through the proxy to upstream is processed and needs authentication, excluding default proxy endpoints.
    - IF the request matches a skipped route (configured via `--skip-auth-route`)
        - Authentication is not enforced, but the proxy will opportunistically attempt to validate a session cookie (`--cookie-name`) or a JWT (`--skip-jwt-bearer-tokens`) if it exists in the request, and inject configured user info or other headers to upstream routes (e.g. `--pass-access-token`)

2. When the authentication is missing but it's necessary, by default the user will be asked to login and will be redirected to the configured IdP's (Identity Provider) login page.

    - IF it is an Ajax request  (i.e. one with `Accept: application/json`)
        - 401 Unauthorized is returned.
    - IF `--skip-jwt-bearer-tokens` is set and request includes an invalid JWT
        - It will redirect to login or return 403 Forbidden if `--bearer-token-login-fallback` is set to false.

3. After returning from the IdP (Identity Provider), the OAuth tokens are stored in the configured session store (cookie or Redis) and a cookie is set.

4. The request is then either forwarded to a configured upstream server with added user info and authentication headers or just returns a valid status code for another proxy / load balancer like Nginx or Traefik to process further. (depending on the configuration)

Notice that the proxy also provides a number of useful [endpoints](features/endpoints.md). 