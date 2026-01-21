---
id: caddy
title: Caddy
---

Integrate OAuth2 Proxy with Caddy v2 using the `forward_auth` directive.

**Key features:**
- Simple forward_auth setup
- Automatic header handling
- Custom error handling and redirects

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
