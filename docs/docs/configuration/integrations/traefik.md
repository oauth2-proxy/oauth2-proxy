---
id: traefik
title: Traefik
---

Set up OAuth2 Proxy with Traefik v2 using the `ForwardAuth` middleware. Includes examples for both error-based redirects and static upstream configurations.

**Key features:**
- ForwardAuth middleware integration
- Error middleware for 401 redirects
- Static upstream configuration (202 responses)
- Dynamic file configuration examples


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

:::note
If you set up your OAuth2 provider to rotate your client secret, you can use the `client-secret-file` option to reload the secret when it is updated.
:::
