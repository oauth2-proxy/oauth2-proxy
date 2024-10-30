---
id: integration
title: Integration
---

## Configuring for use with the Nginx `auth_request` directive

**This option requires `--reverse-proxy` option to be set.**

The [Nginx `auth_request` directive](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) allows Nginx to authenticate requests via the oauth2-proxy's `/auth` endpoint, which only returns a 202 Accepted response or a 401 Unauthorized response without proxying the request through. For example:

```nginx
server {
  listen 443 ssl;
  server_name ...;
  include ssl/ssl.conf;

  location /oauth2/ {
    proxy_pass       http://127.0.0.1:4180;
    proxy_set_header Host                    $host;
    proxy_set_header X-Real-IP               $remote_addr;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
    # or, if you are handling multiple domains:
    # proxy_set_header X-Auth-Request-Redirect $scheme://$host$request_uri;
  }
  location = /oauth2/auth {
    proxy_pass       http://127.0.0.1:4180;
    proxy_set_header Host             $host;
    proxy_set_header X-Real-IP        $remote_addr;
    proxy_set_header X-Forwarded-Uri  $request_uri;
    # nginx auth_request includes headers but not body
    proxy_set_header Content-Length   "";
    proxy_pass_request_body           off;
  }

  location / {
    auth_request /oauth2/auth;
    error_page 401 =403 /oauth2/sign_in;

    # pass information via X-User and X-Email headers to backend,
    # requires running with --set-xauthrequest flag
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;

    # if you enabled --pass-access-token, this will pass the token to the backend
    auth_request_set $token  $upstream_http_x_auth_request_access_token;
    proxy_set_header X-Access-Token $token;

    # if you enabled --cookie-refresh, this is needed for it to work with auth_request
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;

    # When using the --set-authorization-header flag, some provider's cookies can exceed the 4kb
    # limit and so the OAuth2 Proxy splits these into multiple parts.
    # Nginx normally only copies the first `Set-Cookie` header from the auth_request to the response,
    # so if your cookies are larger than 4kb, you will need to extract additional cookies manually.
    auth_request_set $auth_cookie_name_upstream_1 $upstream_cookie_auth_cookie_name_1;

    # Extract the Cookie attributes from the first Set-Cookie header and append them
    # to the second part ($upstream_cookie_* variables only contain the raw cookie content)
    if ($auth_cookie ~* "(; .*)") {
        set $auth_cookie_name_0 $auth_cookie;
        set $auth_cookie_name_1 "auth_cookie_name_1=$auth_cookie_name_upstream_1$1";
    }

    # Send both Set-Cookie headers now if there was a second part
    if ($auth_cookie_name_upstream_1) {
        add_header Set-Cookie $auth_cookie_name_0;
        add_header Set-Cookie $auth_cookie_name_1;
    }

    proxy_pass http://backend/;
    # or "root /path/to/site;" or "fastcgi_pass ..." etc
  }
}
```

When you use ingress-nginx in Kubernetes, you MUST use `kubernetes/ingress-nginx` (which includes the Lua module) and the following configuration snippet for your `Ingress`.
Variables set with `auth_request_set` are not `set`-able in plain nginx config when the location is processed via `proxy_pass` and then may only be processed by Lua.
Note that `nginxinc/kubernetes-ingress` does not include the Lua module.

```yaml
nginx.ingress.kubernetes.io/auth-response-headers: Authorization
nginx.ingress.kubernetes.io/auth-signin: https://$host/oauth2/start?rd=$escaped_request_uri
nginx.ingress.kubernetes.io/auth-url: https://$host/oauth2/auth
nginx.ingress.kubernetes.io/configuration-snippet: |
  auth_request_set $name_upstream_1 $upstream_cookie_name_1;

  access_by_lua_block {
    if ngx.var.name_upstream_1 ~= "" then
      ngx.header["Set-Cookie"] = "name_1=" .. ngx.var.name_upstream_1 .. ngx.var.auth_cookie:match("(; .*)")
    end
  }
```
It is recommended to use `--session-store-type=redis` when expecting large sessions/OIDC tokens (_e.g._ with MS Azure).

You have to substitute *name* with the actual cookie name you configured via --cookie-name parameter. If you don't set a custom cookie name the variable  should be "$upstream_cookie__oauth2_proxy_1" instead of "$upstream_cookie_name_1" and the new cookie-name should be "_oauth2_proxy_1=" instead of "name_1=".

## Configuring for use with the Traefik (v2) `ForwardAuth` middleware

**This option requires `--reverse-proxy` option to be set.**

### ForwardAuth with 401 errors middleware

The [Traefik v2 `ForwardAuth` middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) allows Traefik to authenticate requests via the oauth2-proxy's `/oauth2/auth` endpoint on every request, which only returns a 202 Accepted response or a 401 Unauthorized response without proxying the whole request through. For example, on Dynamic File (YAML) Configuration:

```yaml
http:
  routers:
    a-service:
      rule: "Host(`a-service.example.com`)"
      service: a-service-backend
      middlewares:
        - oauth-errors
        - oauth-auth
      tls:
        certResolver: default
        domains:
          - main: "example.com"
            sans:
              - "*.example.com"
    oauth:
      rule: "Host(`a-service.example.com`, `oauth.example.com`) && PathPrefix(`/oauth2/`)"
      middlewares:
        - auth-headers
      service: oauth-backend
      tls:
        certResolver: default
        domains:
          - main: "example.com"
            sans:
              - "*.example.com"

  services:
    a-service-backend:
      loadBalancer:
        servers:
          - url: http://172.16.0.2:7555
    oauth-backend:
      loadBalancer:
        servers:
          - url: http://172.16.0.1:4180

  middlewares:
    auth-headers:
      headers:
        sslRedirect: true
        stsSeconds: 315360000
        browserXssFilter: true
        contentTypeNosniff: true
        forceSTSHeader: true
        sslHost: example.com
        stsIncludeSubdomains: true
        stsPreload: true
        frameDeny: true
    oauth-auth:
      forwardAuth:
        address: https://oauth.example.com/oauth2/auth
        trustForwardHeader: true
    oauth-errors:
      errors:
        status:
          - "401-403"
        service: oauth-backend
        query: "/oauth2/sign_in?rd={url}"
```

### ForwardAuth with static upstreams configuration

Redirect to sign_in functionality provided without the use of `errors` middleware with [Traefik v2 `ForwardAuth` middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) pointing to oauth2-proxy service's `/` endpoint

**Following options need to be set on `oauth2-proxy`:**
- `--upstream=static://202`: Configures a static response for authenticated sessions
- `--reverse-proxy=true`: Enables the use of `X-Forwarded-*` headers to determine redirects correctly

```yaml
http:
  routers:
    a-service-route-1:
      rule: "Host(`a-service.example.com`, `b-service.example.com`) && PathPrefix(`/`)"
      service: a-service-backend
      middlewares:
        - oauth-auth-redirect # redirects all unauthenticated to oauth2 signin
      tls:
        certResolver: default
        domains:
          - main: "example.com"
            sans:
              - "*.example.com"
    a-service-route-2:
      rule: "Host(`a-service.example.com`) && PathPrefix(`/no-auto-redirect`)"
      service: a-service-backend
      middlewares:
        - oauth-auth-wo-redirect # unauthenticated session will return a 401
      tls:
        certResolver: default
        domains:
          - main: "example.com"
            sans:
              - "*.example.com"
    services-oauth2-route:
      rule: "Host(`a-service.example.com`, `b-service.example.com`) && PathPrefix(`/oauth2/`)"
      middlewares:
        - auth-headers
      service: oauth-backend
      tls:
        certResolver: default
        domains:
          - main: "example.com"
            sans:
              - "*.example.com"
    oauth2-proxy-route:
      rule: "Host(`oauth.example.com`) && PathPrefix(`/`)"
      middlewares:
        - auth-headers
      service: oauth-backend
      tls:
        certResolver: default
        domains:
          - main: "example.com"
            sans:
              - "*.example.com"

  services:
    a-service-backend:
      loadBalancer:
        servers:
          - url: http://172.16.0.2:7555
    b-service-backend:
      loadBalancer:
        servers:
          - url: http://172.16.0.3:7555
    oauth-backend:
      loadBalancer:
        servers:
          - url: http://172.16.0.1:4180

  middlewares:
    auth-headers:
      headers:
        sslRedirect: true
        stsSeconds: 315360000
        browserXssFilter: true
        contentTypeNosniff: true
        forceSTSHeader: true
        sslHost: example.com
        stsIncludeSubdomains: true
        stsPreload: true
        frameDeny: true
    oauth-auth-redirect:
      forwardAuth:
        address: https://oauth.example.com/
        trustForwardHeader: true
        authResponseHeaders:
          - X-Auth-Request-Access-Token
          - Authorization
    oauth-auth-wo-redirect:
      forwardAuth:
        address: https://oauth.example.com/oauth2/auth
        trustForwardHeader: true
        authResponseHeaders:
          - X-Auth-Request-Access-Token
          - Authorization
```

## Configuring for use with the Caddy (v2) `forward_auth` directive

The [Caddy `forward_auth` directive](https://caddyserver.com/docs/caddyfile/directives/forward_auth) allows Caddy to authenticate requests via the `oauth2-proxy`'s `/auth`.

This example is for a simple reverse proxy setup where the `/oauth2/` path is kept under the same domain and failed auth requests (401 status returned) will be caught and redirected to the `sign_in` endpoint.

**Following options need to be set on `oauth2-proxy`:**
- `--reverse-proxy=true`: Enables the use of `X-Forwarded-*` headers to determine redirects correctly

```nginx title="Caddyfile"
example.com {
	# Requests to /oauth2/* are proxied to oauth2-proxy without authentication.
	# You can't use `reverse_proxy /oauth2/* oauth2-proxy.internal:4180` here because the reverse_proxy directive has lower precedence than the handle directive.
	handle /oauth2/* {
		reverse_proxy oauth2-proxy.internal:4180 {
			# oauth2-proxy requires the X-Real-IP and X-Forwarded-{Proto,Host,Uri} headers.
			# The reverse_proxy directive automatically sets X-Forwarded-{For,Proto,Host} headers.
			header_up X-Real-IP {remote_host}
			header_up X-Forwarded-Uri {uri}
		}
	}

	# Requests to other paths are first processed by oauth2-proxy for authentication.
	handle {
		forward_auth oauth2-proxy.internal:4180 {
			uri /oauth2/auth

			# oauth2-proxy requires the X-Real-IP and X-Forwarded-{Proto,Host,Uri} headers.
			# The forward_auth directive automatically sets the X-Forwarded-{For,Proto,Host,Method,Uri} headers.
			header_up X-Real-IP {remote_host}

			# If needed, you can copy headers from the oauth2-proxy response to the request sent to the upstream.
			# Make sure to configure the --set-xauthrequest flag to enable this feature.
			#copy_headers X-Auth-Request-User X-Auth-Request-Email

			# If oauth2-proxy returns a 401 status, redirect the client to the sign-in page.
			@error status 401
			handle_response @error {
				redir * /oauth2/sign_in?rd={scheme}://{host}{uri}
			}
		}

		# If oauth2-proxy returns a 2xx status, the request is then proxied to the upstream.
		reverse_proxy upstream.internal:3000
	}
}
```

:::note
If you set up your OAuth2 provider to rotate your client secret, you can use the `client-secret-file` option to reload the secret when it is updated.
:::
