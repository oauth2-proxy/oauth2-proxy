---
id: behaviour
title: Behaviour
---


1. Any request passing through the proxy to upstream is processed and needs authentication, excluding default proxy endpoints. If the request matches a skipped route (configured via `--skip-auth-route`), authentication is not enforced, but proxy still attempts to validate a session cookie (`--cookie-name`) if any, and injects configured headers to upstream routes (e.g. `--pass-access-token`)

2. If authentication is required but missing then the user is asked to log in and redirected to the authentication provider (unless it is an Ajax request, i.e. one with `Accept: application/json`, in which case 401 Unauthorized is returned)

3. After returning from the authentication provider, the oauth tokens are stored in the configured session store (cookie, redis, ...) and a cookie is set

4. The request is forwarded to the upstream server with added user info and authentication headers (depending on the configuration)


Notice that the proxy also provides a number of useful [endpoints](features/endpoints.md). 