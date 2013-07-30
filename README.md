google_auth_proxy
=================


A reverse proxy that provides authentication using Google OAuth2 to validate 
individual accounts, or a whole google apps domain.

[![Build Status](https://secure.travis-ci.org/bitly/google_auth_proxy.png?branch=master)](http://travis-ci.org/bitly/google_auth_proxy)


## Architecture

```
    _______       ___________________       __________
    |Nginx| ----> |google_auth_proxy| ----> |upstream| 
    -------       -------------------       ----------
                          ||
                          \/
                  [google oauth2 api]
```


## Installation

1. [Install Go](http://golang.org/doc/install)
2. `$ go get github.com/bitly/google_auth_proxy`. This should put the binary in `$GOROOT/bin`

## OAuth Configuration

You will need to register an OAuth application with google, and configure it with Redirect URI(s) for the domain you
intend to run google_auth_proxy on.

1. Visit to Google Api Console https://code.google.com/apis/console/
2. under "API Access", choose "Create an OAuth 2.0 Client ID"
3. Edit the application settings, and list the Redirect URI(s) where you will run your application. For example: 
`https://internalapp.yourcompany.com/oauth2/callback`
4. Make a note of the Client ID, and Client Secret and specify those values as command line arguments

## Command Line Options

```
Usage of ./google_auth_proxy:
  -authenticated-emails-file="": authenticate against emails via file (one per line)
  -client-id="": the Google OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret="": the OAuth Client Secret
  -cookie-domain="": an optional cookie domain to force cookies to
  -cookie-secret="": the seed string for secure cookies
  -google-apps-domain="": authenticate against the given google apps domain
  -htpasswd-file="": additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address="127.0.0.1:4180": <addr>:<port> to listen on for HTTP clients
  -pass-basic-auth=true: pass HTTP Basic Auth information to upstream
  -redirect-url="": the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -upstream=[]: the http url(s) of the upstream endpoint. If multiple, routing is based on path
  -version=false: print version string
```


## Example Configuration

This example has a [Nginx](http://nginx.org/) SSL endpoint proxying to `google_auth_proxy` on port `4180`. 
`google_auth_proxy` then authenticates requests for an upstream application running on port `8080`. The external 
endpoint for this example would be `https://internal.yourcompany.com/`.

An example Nginx config follows. Note the use of `Strict-Transport-Security` header to pin requests to SSL 
via [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security):

```
server {
    listen 443 default ssl;
    server_name internal.yourcompany.com;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/cert.key;
    add_header Strict-Transport-Security max-age=1209600;

    location / {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_connect_timeout 1;
        proxy_send_timeout 30;
        proxy_read_timeout 30;
    }
}
```

The command line to run `google_auth_proxy` would look like this:

```bash
./google_auth_proxy \
   --redirect-url="https://internal.yourcompany.com/oauth2/callback"  \
   --google-apps-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --cookie-secret=... \
   --client-id=... \
   --client-secret=...
```

## Environment variables

The environment variables `google_auth_client_id`, `google_auth_secret` and `google_auth_cookie_secret` can be used in place of the corresponding command-line arguments.

## Endpoint Documentation

Google auth proxy responds directly to the following endpoints. All other endpoints will be authenticated.

* /oauth2/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
* /oauth2/start - a URL that will redirect to start the oauth cycle
* /oauth2/callback - the URL used at the end of the oauth cycle
