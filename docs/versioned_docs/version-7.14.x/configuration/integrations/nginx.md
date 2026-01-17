---
id: nginx
title: Nginx
---

Configure OAuth2 Proxy with Nginx using the `auth_request` directive. Includes examples for both standalone Nginx configurations and Kubernetes ingress-nginx with annotations.

**Key features:**
- Support for `auth_request` directive
- Kubernetes Ingress annotations
- Multi-part cookie handling for large tokens
- Session refresh support

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

When you use ingress-nginx in Kubernetes, you can configure the same behavior with the following annotations on your Ingress resource:

```yaml
nginx.ingress.kubernetes.io/auth-url: "https://<oauth2-proxy-fqdn>/oauth2/auth"
nginx.ingress.kubernetes.io/auth-signin: "https://<oauth2-proxy-fqdn>/oauth2/start?rd=$escaped_request_uri"
```

This minimal configuration works for standard authentication flows. Lua/cookie handling is only needed for advanced scenarios (e.g., multi-part cookies, custom session logic). See the official ingress-nginx example: https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/.

It is recommended to use `--session-store-type=redis` when expecting large sessions/OIDC tokens (_e.g._ with MS Azure).

:::tip Kubernetes Dashboard with Azure Entra ID
For a complete example of integrating oauth2-proxy with Kubernetes Dashboard on AKS using Azure Entra ID, including RBAC configuration and troubleshooting, see the [Kubernetes Dashboard on AKS](../providers/ms_entra_id.md#kubernetes-dashboard-on-aks) section in the Microsoft Entra ID provider documentation.
:::

You have to substitute *name* with the actual cookie name you configured via --cookie-name parameter. If you don't set a custom cookie name the variable  should be "$upstream_cookie__oauth2_proxy_1" instead of "$upstream_cookie_name_1" and the new cookie-name should be "_oauth2_proxy_1=" instead of "name_1=".

:::note
If you set up your OAuth2 provider to rotate your client secret, you can use the `client-secret-file` option to reload the secret when it is updated.
:::
