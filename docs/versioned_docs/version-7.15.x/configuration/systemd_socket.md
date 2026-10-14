---
id: systemd_socket
title: Systemd Socket Activation
---

Pass an existing listener created by systemd.socket to oauth2-proxy.

To do this create a socket:

oauth2-proxy.socket
```
[Socket]
ListenStream=%t/oauth2.sock
SocketGroup=www-data
SocketMode=0660
```

Now it's possible to call this socket from e.g. nginx:
```
server {
    location /oauth2/ {
      proxy_pass http://unix:/run/oauth2-proxy/oauth2.sock;
}
```

The oauth2-proxy should have `--http-address=fd:3` as a parameter.
Here fd is case insensitive and means file descriptor. The number 3 refers to the first non-stdin/stdout/stderr file descriptor,
systemd-socket-activate (which is what systemd.socket uses), listens to what it is told and passes
the listener it created onto the process, starting with file descriptor 3.

```
./oauth2-proxy \
    --http-address="fd:3" \
    --email-domain="yourcompany.com"  \
    --upstream=http://127.0.0.1:8080/ \
    --cookie-secret=... \
    --cookie-secure=true \
    --provider=... \
    --client-id=... \
    --client-secret=...
```

## Trusted IPs

When listening on a Unix socket, Go sets `http.Request.RemoteAddr` to `"@"` instead of the usual `"host:port"` format. This means there is no client IP available from the connection itself.

As a result, `--trusted-ip` entries cannot match against the direct connection address for Unix socket listeners. Requests arriving over a Unix socket will never be considered "trusted" based on their `RemoteAddr`. IP-based trust decisions will still work if a trusted reverse proxy sets `X-Forwarded-For` or `X-Real-IP` headers and `--reverse-proxy=true` is configured.

## TLS

Currently TLS is not supported (but it's doable).
