oaut2_proxy
=================

(This project was formerly known as Google Auth Proxy)

A reverse proxy that provides authentication using Providers (Google, Github, and others)
to validate individual accounts, or a whole email domain.

[![Build Status](https://secure.travis-ci.org/bitly/oauth2_proxy.png?branch=master)](http://travis-ci.org/bitly/oauth2_proxy)


![sign_in_page](https://cloud.githubusercontent.com/assets/45028/4970624/7feb7dd8-6886-11e4-93e0-c9904af44ea8.png)

## Architecture

```
    _______       ______________       __________
    |Nginx| ----> |oauth2_proxy| ----> |upstream| 
    -------       --------------       ----------
                        ||
                        \/
              [provider OAuth2 API]
```


## Installation

1. Download [Prebuilt Binary](https://github.com/bitly/oauth2_proxy/releases) or build from `master` with `$ go get github.com/bitly/oauth2_proxy` which should put the binary in `$GOROOT/bin`
2. Register an OAuth Application with a Provider
3. Configure Google Auth Proxy using config file, command line options, or environment variables
4. Deploy behind a SSL endpoint (example provided for Nginx)

## OAuth Configuration

You will need to register an OAuth application with Google (or [another
provider](#providers)), and configure it with Redirect URI(s) for the domain
you intend to run `OAUTH2_PROXY` on.

For Google, the registration steps are:

1. Create a new project: https://console.developers.google.com/project
2. Under "APIs & Auth", choose "Credentials"
3. Now, choose "Create new Client ID"
   * The Application Type should be **Web application**
   * Enter your domain in the Authorized Javascript Origins `https://internal.yourcompany.com`
   * Enter the correct Authorized Redirect URL `https://internal.yourcompany.com/oauth2/callback`
     * NOTE: `oauth2_proxy` will _only_ callback on the path `/oauth2/callback`
4. Under "APIs & Auth" choose "Consent Screen"
   * Fill in the necessary fields and Save (this is _required_)
5. Take note of the **Client ID** and **Client Secret**

For LinkedIn, the registration steps are:

1. Create a new project: https://www.linkedin.com/secure/developer
2. In the OAuth User Agreement section:
   * In default scope, select r_basicprofile and r_emailaddress.
   * In "OAuth 2.0 Redirect URLs", enter `https://internal.yourcompany.com/oauth2/callback`
3. Fill in the remaining required fields and Save.
4. Take note of the **Consumer Key / API Key** and **Consumer Secret / Secret Key**

## Configuration

`oauth2_proxy` can be configured via [config file](#config-file), [command line options](#command-line-options) or [environment variables](#environment-variables).

### Config File

An example [OAUTH2_PROXY.cfg](contrib/oauth2_proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `-config=/etc/oauth2_proxy.cfg`

### Command Line Options

```
Usage of oauth2_proxy:
  -authenticated-emails-file="": authenticate against emails via file (one per line)
  -client-id="": the OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret="": the Client Secret
  -config="": path to config file
  -cookie-domain="": an optional cookie domain to force cookies to (ie: .yourcompany.com)*
  -cookie-expire=168h0m0s: expire timeframe for cookie
  -cookie-httponly=true: set HttpOnly cookie flag
  -cookie-https-only=true: set secure (HTTPS) cookies (deprecated. use --cookie-secure setting)
  -cookie-refresh=0: refresh the cookie when less than this much time remains before expiration; 0 to disable
  -cookie-secret="": the seed string for secure cookies
  -cookie-secure=true: set secure (HTTPS) cookie flag
  -custom-templates-dir="": path to custom html templates
  -display-htpasswd-form=true: display username / password login form if an htpasswd file is provided
  -google-apps-domain=: authenticate against the given Google apps domain (may be given multiple times)
  -htpasswd-file="": additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address="127.0.0.1:4180": [http://]<addr>:<port> or unix://<path> to listen on for HTTP clients
  -login-url="": Authentication endpoint
  -pass-access-token=false: pass OAuth access_token to upstream via X-Forwarded-Access-Token header
  -pass-basic-auth=true: pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream
  -pass-host-header=true: pass the request Host Header to upstream
  -profile-url="": Profile access endpoint
  -provider="": Oauth provider (defaults to Google)
  -redeem-url="": Token redemption endpoint
  -redirect-url="": the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -request-logging=true: Log requests to stdout
  -scope="": Oauth scope specification
  -skip-auth-regex=: bypass authentication for requests path's that match (may be given multiple times)
  -upstream=: the http url(s) of the upstream endpoint. If multiple, routing is based on path
  -validate-url="": Access token validation endpoint
  -version=false: print version string
```

See below for provider specific options

### Environment variables

The environment variables `OAUTH2_PROXY_CLIENT_ID`, `OAUTH2_PROXY_CLIENT_SECRET`, `OAUTH2_PROXY_COOKIE_SECRET`, `OAUTH2_PROXY_COOKIE_DOMAIN` and `OAUTH2_PROXY_COOKIE_EXPIRE` can be used in place of the corresponding command-line arguments.

### Example Nginx Configuration

This example has a [Nginx](http://nginx.org/) SSL endpoint proxying to `oauth2_proxy` on port `4180`. 
`oauth2_proxy` then authenticates requests for an upstream application running on port `8080`. The external 
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

The command line to run `oauth2_proxy` would look like this:

```bash
./oauth2_proxy \
   --google-apps-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --cookie-secret=... \
   --cookie-secure=true \
   --client-id=... \
   --client-secret=...
```


## Endpoint Documentation

OAuth2 Proxy responds directly to the following endpoints. All other endpoints will be proxied upstream when authenticated.

* /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
* /ping - returns an 200 OK response
* /oauth2/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
* /oauth2/start - a URL that will redirect to start the OAuth cycle
* /oauth2/callback - the URL used at the end of the OAuth cycle. The oauth app will be configured with this ass the callback url.

## Logging Format

OAuth2 Proxy Proxy logs requests to stdout in a format similar to Apache Combined Log.

```
<REMOTE_ADDRESS> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

## <a name="providers"></a>Providers

Authentication providers can be specified by the `providers` flag/config
directive. Right now this includes:

* `google` - (default) [Google](https://console.developers.google.com/project)
* `myusa` - The [MyUSA](https://alpha.my.usa.gov) authentication service
  ([GitHub](https://github.com/18F/myusa))
* `linkedin` - The [LinkedIn](https://developer.linkedin.com/docs/signin-with-linkedin) Sign In service.
* `github` - Via [Github][https://github.com/settings/developers] OAuth App. Also supports restricting via org and team.

    -github-org="": restrict logins to members of this organisation
    -github-team="": restrict logins to members of this team

## Adding a new Provider

Follow the examples in the [`providers` package](providers/) to define a new
`Provider` instance. Add a new `case` to
[`providers.New()`](providers/providers.go) to allow the auth proxy to use the
new `Provider`.
