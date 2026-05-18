---
id: tls
title: TLS Configuration
---

There are two recommended configurations:
- [At OAuth2 Proxy](#terminate-tls-at-oauth2-proxy)
- [At Reverse Proxy](#terminate-tls-at-reverse-proxy-eg-nginx)

### Terminate TLS at OAuth2 Proxy

1.  Configure SSL Termination with OAuth2 Proxy by providing a `--tls-cert-file=/path/to/cert.pem` and `--tls-key-file=/path/to/cert.key`.

    The command line to run `oauth2-proxy` in this configuration would look like this:

    ```bash
    ./oauth2-proxy \
        --email-domain="yourcompany.com"  \
        --upstream=http://127.0.0.1:8080/ \
        --tls-cert-file=/path/to/cert.pem \
        --tls-key-file=/path/to/cert.key \
        --cookie-secret=... \
        --cookie-secure=true \
        --provider=... \
        --client-id=... \
        --client-secret=...
    ```

2.  With this configuration approach the customization of the TLS settings is limited.

    The minimal acceptable TLS version can be set with `--tls-min-version=TLS1.3`. 
    The defaults set `TLS1.2` as the minimal version. 
    Regardless of the minimum version configured, `TLS1.3` is currently always used as the maximal version.

    TLS server side cipher suites can be specified with `--tls-cipher-suite=TLS_RSA_WITH_RC4_128_SHA`.
    If not specified, the defaults from [`crypto/tls`](https://pkg.go.dev/crypto/tls#CipherSuites) of the currently used `go` version for building `oauth2-proxy` will be used.
    A complete list of valid TLS cipher suite names can be found in [`crypto/tls`](https://pkg.go.dev/crypto/tls#pkg-constants).

### Terminate TLS at Reverse Proxy, e.g. Nginx

1.  Configure SSL Termination with [Nginx](http://nginx.org/) (example config below), Amazon ELB, Google Cloud Platform Load Balancing, or ...

    Because `oauth2-proxy` listens on `127.0.0.1:4180` by default, to listen on all interfaces (needed when using an
    external load balancer like Amazon ELB or Google Platform Load Balancing) use `--http-address="0.0.0.0:4180"` or
    `--http-address="http://:4180"`.

    Nginx will listen on port `443` and handle SSL connections while proxying to `oauth2-proxy` on port `4180`.
    `oauth2-proxy` will then authenticate requests for an upstream application. The external endpoint for this example
    would be `https://internal.yourcompany.com/`.

    An example Nginx config follows. Note the use of `Strict-Transport-Security` header to pin requests to SSL
    via [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security):

    ```
    server {
        listen 443 default ssl;
        server_name internal.yourcompany.com;
        ssl_certificate /path/to/cert.pem;
        ssl_certificate_key /path/to/cert.key;
        add_header Strict-Transport-Security max-age=2592000;

        location / {
            proxy_pass http://127.0.0.1:4180;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_connect_timeout 1;
            proxy_send_timeout 30;
            proxy_read_timeout 30;
        }
    }
    ```

2.  The command line to run `oauth2-proxy` in this configuration would look like this:

    ```bash
    ./oauth2-proxy \
       --email-domain="yourcompany.com"  \
       --upstream=http://127.0.0.1:8080/ \
       --cookie-secret=... \
       --cookie-secure=true \
       --provider=... \
       --reverse-proxy=true \
       --client-id=... \
       --client-secret=...
    ```
