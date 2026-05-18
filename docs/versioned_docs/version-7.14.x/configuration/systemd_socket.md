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

Currently TLS is not supported (but it's doable).
