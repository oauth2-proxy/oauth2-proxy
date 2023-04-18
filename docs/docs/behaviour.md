---
id: behaviour
title: Behaviour
---

1. Any request passing through the proxy (and not matched by `--skip-auth-regex`) is checked for the proxy's session cookie (`--cookie-name`) (or, if allowed, a JWT token - see `--skip-jwt-bearer-tokens`).
2. If authentication is required but missing then the user is asked to log in and redirected to the authentication provider (unless it is an Ajax request, i.e. one with `Accept: application/json`, in which case 401 Unauthorized is returned)
3. After returning from the authentication provider, the oauth tokens are stored in the configured session store (cookie, redis, ...) and a cookie is set
4. The request is forwarded to the upstream server with added user info and authentication headers (depending on the configuration)

The log in interface will, by default, redirect back to the configured domain with the user's original path.
If you wish to use the same oauth proxy instance across multiple domains, you can specify the `X-Auth-Request-Redirect` header via a proxy to refer to the domain you want to redirect to after authentication along with the path.
For example, with nginx you would use the `proxy_set_header` directive:

```
proxy_set_header X-Auth-Request-Redirect $scheme://$http_host$request_uri;
```

Notice that the proxy also provides a number of useful [endpoints](features/endpoints.md).
