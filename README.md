oauth2_proxy
=================

A reverse proxy and static file server that provides authentication using Providers (Google, GitHub, and others)
to validate accounts by email, domain or group.

[![Build Status](https://secure.travis-ci.org/bitly/oauth2_proxy.svg?branch=master)](http://travis-ci.org/bitly/oauth2_proxy)


![Sign In Page](https://cloud.githubusercontent.com/assets/45028/4970624/7feb7dd8-6886-11e4-93e0-c9904af44ea8.png)

## Architecture

![OAuth2 Proxy Architecture](https://cloud.githubusercontent.com/assets/45028/8027702/bd040b7a-0d6a-11e5-85b9-f8d953d04f39.png)

## Installation

1. Download [Prebuilt Binary](https://github.com/bitly/oauth2_proxy/releases) (current release is `v2.2`) or build with `$ go get github.com/bitly/oauth2_proxy` which will put the binary in `$GOROOT/bin`
Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v2.3`.
```
sha256sum -c sha256sum.txt 2>&1 | grep OK
oauth2_proxy-2.3.linux-amd64: OK
```
2. Select a Provider and Register an OAuth Application with a Provider
3. Configure OAuth2 Proxy using config file, command line options, or environment variables
4. Configure SSL or Deploy behind a SSL endpoint (example provided for Nginx)

## OAuth Provider Configuration

You will need to register an OAuth application with a Provider (Google, GitHub or another provider), and configure it with Redirect URI(s) for the domain you intend to run `oauth2_proxy` on.

Valid providers are :

* [Google](#google-auth-provider) *default*
* [Azure](#azure-auth-provider)
* [Facebook](#facebook-auth-provider)
* [GitHub](#github-auth-provider)
* [GitLab](#gitlab-auth-provider)
* [LinkedIn](#linkedin-auth-provider)

The provider can be selected using the `provider` configuration value.

### Google Auth Provider

For Google, the registration steps are:

1. Create a new project: https://console.developers.google.com/project
2. Choose the new project from the top right project dropdown (only if another project is selected)
3. In the project Dashboard center pane, choose **"API Manager"**
4. In the left Nav pane, choose **"Credentials"**
5. In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
6. In the center pane, choose **"Credentials"** tab.
   * Open the **"New credentials"** drop down
   * Choose **"OAuth client ID"**
   * Choose **"Web application"**
   * Application name is freeform, choose something appropriate
   * Authorized JavaScript origins is your domain ex: `https://internal.yourcompany.com`
   * Authorized redirect URIs is the location of oauth2/callback ex: `https://internal.yourcompany.com/oauth2/callback`
   * Choose **"Create"**
4. Take note of the **Client ID** and **Client Secret**

It's recommended to refresh sessions on a short interval (1h) with `cookie-refresh` setting which validates that the account is still authorized.

#### Restrict auth to specific Google groups on your domain. (optional)

1. Create a service account: https://developers.google.com/identity/protocols/OAuth2ServiceAccount and make sure to download the json file.
2. Make note of the Client ID for a future step.
3. Under "APIs & Auth", choose APIs.
4. Click on Admin SDK and then Enable API.
5. Follow the steps on https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account and give the client id from step 2 the following oauth scopes:
```
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.user.readonly
```
6. Follow the steps on https://support.google.com/a/answer/60757 to enable Admin API access.
7. Create or choose an existing administrative email address on the Gmail domain to assign to the ```google-admin-email``` flag. This email will be impersonated by this client to make calls to the Admin SDK. See the note on the link from step 5 for the reason why.
8. Create or choose an existing email group and set that email to the ```google-group``` flag. You can pass multiple instances of this flag with different groups
and the user will be checked against all the provided groups.
9. Lock down the permissions on the json file downloaded from step 1 so only oauth2_proxy is able to read the file and set the path to the file in the ```google-service-account-json``` flag.
10. Restart oauth2_proxy.

Note: The user is checked against the group members list on initial authentication and every time the token is refreshed ( about once an hour ).

### Azure Auth Provider

1. [Add an application](https://azure.microsoft.com/en-us/documentation/articles/active-directory-integrating-applications/) to your Azure Active Directory tenant.
2. On the App properties page provide the correct Sign-On URL ie `https://internal.yourcompany.com/oauth2/callback`
3. If applicable take note of your `TenantID` and provide it via the `--azure-tenant=<YOUR TENANT ID>` commandline option. Default the `common` tenant is used.

The Azure AD auth provider uses `openid` as it default scope. It uses `https://graph.windows.net` as a default protected resource. It call to `https://graph.windows.net/me` to get the email address of the user that logs in.


### Facebook Auth Provider

1. Create a new FB App from <https://developers.facebook.com/>
2. Under FB Login, set your Valid OAuth redirect URIs to `https://internal.yourcompany.com/oauth2/callback`

### GitHub Auth Provider

1. Create a new project: https://github.com/settings/developers
2. Under `Authorization callback URL` enter the correct url ie `https://internal.yourcompany.com/oauth2/callback`

The GitHub auth provider supports two additional parameters to restrict authentication to Organization or Team level access. Restricting by org and team is normally accompanied with `--email-domain=*`

    -github-org="": restrict logins to members of this organisation
    -github-team="": restrict logins to members of any of these teams (slug), separated by a comma

If you are using GitHub enterprise, make sure you set the following to the appropriate url:

    -login-url="http(s)://<enterprise github host>/login/oauth/authorize"
    -redeem-url="http(s)://<enterprise github host>/login/oauth/access_token"
    -validate-url="http(s)://<enterprise github host>/api/v3"

### GitLab Auth Provider

Whether you are using GitLab.com or self-hosting GitLab, follow [these steps to add an application](http://doc.gitlab.com/ce/integration/oauth_provider.html)

If you are using self-hosted GitLab, make sure you set the following to the appropriate URL:

    -login-url="<your gitlab url>/oauth/authorize"
    -redeem-url="<your gitlab url>/oauth/token"
    -validate-url="<your gitlab url>/api/v4/user"


### LinkedIn Auth Provider

For LinkedIn, the registration steps are:

1. Create a new project: https://www.linkedin.com/secure/developer
2. In the OAuth User Agreement section:
   * In default scope, select r_basicprofile and r_emailaddress.
   * In "OAuth 2.0 Redirect URLs", enter `https://internal.yourcompany.com/oauth2/callback`
3. Fill in the remaining required fields and Save.
4. Take note of the **Consumer Key / API Key** and **Consumer Secret / Secret Key**

### Microsoft Azure AD Provider

For adding an application to the Microsoft Azure AD follow [these steps to add an application](https://azure.microsoft.com/en-us/documentation/articles/active-directory-integrating-applications/).

Take note of your `TenantId` if applicable for your situation. The `TenantId` can be used to override the default `common` authorization server with a tenant specific server.

### OpenID Connect Provider

OpenID Connect is a spec for OAUTH 2.0 + identity that is implemented by many major providers and several open source projects. This provider was originally built against CoreOS Dex and we will use it as an example.

1. Launch a Dex instance using the [getting started guide](https://github.com/coreos/dex/blob/master/Documentation/getting-started.md).
2. Setup oauth2_proxy with the correct provider and using the default ports and callbacks.
3. Login with the fixture use in the dex guide and run the oauth2_proxy with the following args:

    -provider oidc
    -client-id oauth2_proxy
    -client-secret proxy
    -redirect-url http://127.0.0.1:4180/oauth2/callback
    -oidc-issuer-url http://127.0.0.1:5556
    -cookie-secure=false
    -email-domain example.com

## Email Authentication

To authorize by email domain use `--email-domain=yourcompany.com`. To authorize individual email addresses use `--authenticated-emails-file=/path/to/file` with one email per line. To authorize all email addresses use `--email-domain=*`.

## Configuration

`oauth2_proxy` can be configured via [config file](#config-file), [command line options](#command-line-options) or [environment variables](#environment-variables).

To generate a strong cookie secret use `python -c 'import os,base64; print base64.urlsafe_b64encode(os.urandom(16))'`

### Config File

An example [oauth2_proxy.cfg](contrib/oauth2_proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `-config=/etc/oauth2_proxy.cfg`

### Command Line Options

```
Usage of oauth2_proxy:
  -approval-prompt string: OAuth approval_prompt (default "force")
  -authenticated-emails-file string: authenticate against emails via file (one per line)
  -azure-tenant string: go to a tenant-specific or common (tenant-independent) endpoint. (default "common")
  -basic-auth-password string: the password to set when passing the HTTP Basic Auth header
  -client-id string: the OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret string: the OAuth Client Secret
  -config string: path to config file
  -cookie-domain string: an optional cookie domain to force cookies to (ie: .yourcompany.com)
  -cookie-expire duration: expire timeframe for cookie (default 168h0m0s)
  -cookie-httponly: set HttpOnly cookie flag (default true)
  -cookie-name string: the name of the cookie that the oauth_proxy creates (default "_oauth2_proxy")
  -cookie-refresh duration: refresh the cookie after this duration; 0 to disable
  -cookie-secret string: the seed string for secure cookies (optionally base64 encoded)
  -cookie-secure: set secure (HTTPS) cookie flag (default true)
  -custom-templates-dir string: path to custom html templates
  -display-htpasswd-form: display username / password login form if an htpasswd file is provided (default true)
  -email-domain value: authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email
  -footer string: custom footer string. Use "-" to disable default footer.
  -github-org string: restrict logins to members of this organisation
  -github-team string: restrict logins to members of any of these teams (slug), separated by a comma
  -google-admin-email string: the google admin to impersonate for api calls
  -google-group value: restrict logins to members of this google group (may be given multiple times).
  -google-service-account-json string: the path to the service account json credentials
  -htpasswd-file string: additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address string: [http://]<addr>:<port> or unix://<path> to listen on for HTTP clients (default "127.0.0.1:4180")
  -https-address string: <addr>:<port> to listen on for HTTPS clients (default ":443")
  -login-url string: Authentication endpoint
  -pass-access-token: pass OAuth access_token to upstream via X-Forwarded-Access-Token header
  -pass-basic-auth: pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -pass-host-header: pass the request Host Header to upstream (default true)
  -pass-user-headers: pass X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -profile-url string: Profile access endpoint
  -provider string: OAuth provider (default "google")
  -proxy-prefix string: the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in) (default "/oauth2")
  -redeem-url string: Token redemption endpoint
  -redirect-url string: the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -request-logging: Log requests to stdout (default true)
  -request-logging-format: Template for request log lines (see "Logging Format" paragraph below)
  -resource string: The resource that is protected (Azure AD only)
  -scope string: OAuth scope specification
  -set-xauthrequest: set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)
  -signature-key string: GAP-Signature request signature key (algorithm:secretkey)
  -skip-auth-preflight: will skip authentication for OPTIONS requests
  -skip-auth-regex value: bypass authentication for requests path's that match (may be given multiple times)
  -skip-provider-button: will skip sign-in-page to directly reach the next step: oauth/start
  -ssl-insecure-skip-verify: skip validation of certificates presented when using HTTPS
  -tls-cert string: path to certificate file
  -tls-key string: path to private key file
  -upstream value: the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path
  -validate-url string: Access token validation endpoint
  -version: print version string
```

See below for provider specific options

### Upstreams Configuration

`oauth2_proxy` supports having multiple upstreams, and has the option to pass requests on to HTTP(S) servers or serve static files from the file system. HTTP and HTTPS upstreams are configured by providing a URL such as `http://127.0.0.1:8080/` for the upstream parameter, that will forward all authenticated requests to be forwarded to the upstream server. If you instead provide `http://127.0.0.1:8080/some/path/` then it will only be requests that start with `/some/path/` which are forwarded to the upstream.

Static file paths are configured as a file:// URL. `file:///var/www/static/` will serve the files from that directory at `http://[oauth2_proxy url]/var/www/static/`, which may not be what you want. You can provide the path to where the files should be available by adding a fragment to the configured URL. The value of the fragment will then be used to specify which path the files are available at. `file:///var/www/static/#/static/` will ie. make `/var/www/static/` available at `http://[oauth2_proxy url]/static/`.

Multiple upstreams can either be configured by supplying a comma separated list to the `-upstream` parameter, supplying the parameter multiple times or provinding a list in the [config file](#config-file). When multiple upstreams are used routing to them will be based on the path they are set up with.

### Environment variables

The following environment variables can be used in place of the corresponding command-line arguments:

- `OAUTH2_PROXY_CLIENT_ID`
- `OAUTH2_PROXY_CLIENT_SECRET`
- `OAUTH2_PROXY_COOKIE_NAME`
- `OAUTH2_PROXY_COOKIE_SECRET`
- `OAUTH2_PROXY_COOKIE_DOMAIN`
- `OAUTH2_PROXY_COOKIE_EXPIRE`
- `OAUTH2_PROXY_COOKIE_REFRESH`
- `OAUTH2_PROXY_SIGNATURE_KEY`

## SSL Configuration

There are two recommended configurations.

1) Configure SSL Termination with OAuth2 Proxy by providing a `--tls-cert=/path/to/cert.pem` and `--tls-key=/path/to/cert.key`.

The command line to run `oauth2_proxy` in this configuration would look like this:

```bash
./oauth2_proxy \
   --email-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --tls-cert=/path/to/cert.pem \
   --tls-key=/path/to/cert.key \
   --cookie-secret=... \
   --cookie-secure=true \
   --provider=... \
   --client-id=... \
   --client-secret=...
```


2) Configure SSL Termination with [Nginx](http://nginx.org/) (example config below), Amazon ELB, Google Cloud Platform Load Balancing, or ....

Because `oauth2_proxy` listens on `127.0.0.1:4180` by default, to listen on all interfaces (needed when using an
external load balancer like Amazon ELB or Google Platform Load Balancing) use `--http-address="0.0.0.0:4180"` or
`--http-address="http://:4180"`.

Nginx will listen on port `443` and handle SSL connections while proxying to `oauth2_proxy` on port `4180`.
`oauth2_proxy` will then authenticate requests for an upstream application. The external endpoint for this example
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
        proxy_set_header X-Scheme $scheme;
        proxy_connect_timeout 1;
        proxy_send_timeout 30;
        proxy_read_timeout 30;
    }
}
```

The command line to run `oauth2_proxy` in this configuration would look like this:

```bash
./oauth2_proxy \
   --email-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --cookie-secret=... \
   --cookie-secure=true \
   --provider=... \
   --client-id=... \
   --client-secret=...
```

## Endpoint Documentation

OAuth2 Proxy responds directly to the following endpoints. All other endpoints will be proxied upstream when authenticated. The `/oauth2` prefix can be changed with the `--proxy-prefix` config variable.

* /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
* /ping - returns an 200 OK response
* /oauth2/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
* /oauth2/start - a URL that will redirect to start the OAuth cycle
* /oauth2/callback - the URL used at the end of the OAuth cycle. The oauth app will be configured with this as the callback url.
* /oauth2/auth - only returns a 202 Accepted response or a 401 Unauthorized response; for use with the [Nginx `auth_request` directive](#nginx-auth-request)

## Request signatures

If `signature_key` is defined, proxied requests will be signed with the
`GAP-Signature` header, which is a [Hash-based Message Authentication Code
(HMAC)](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
of selected request information and the request body [see `SIGNATURE_HEADERS`
in `oauthproxy.go`](./oauthproxy.go).

`signature_key` must be of the form `algorithm:secretkey`, (ie: `signature_key = "sha1:secret0"`)

For more information about HMAC request signature validation, read the
following:

* [Amazon Web Services: Signing and Authenticating REST
  Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
* [rc3.org: Using HMAC to authenticate Web service
  requests](http://rc3.org/2011/12/02/using-hmac-to-authenticate-web-service-requests/)

## Logging Format

By default, OAuth2 Proxy logs requests to stdout in a format similar to Apache Combined Log.

```
<REMOTE_ADDRESS> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

If you require a different format than that, you can configure it with the `-request-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}
```

[See `logMessageData` in `logging_handler.go`](./logging_handler.go) for all available variables.

## Adding a new Provider

Follow the examples in the [`providers` package](providers/) to define a new
`Provider` instance. Add a new `case` to
[`providers.New()`](providers/providers.go) to allow `oauth2_proxy` to use the
new `Provider`.

## <a name="nginx-auth-request"></a>Configuring for use with the Nginx `auth_request` directive

The [Nginx `auth_request` directive](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) allows Nginx to authenticate requests via the oauth2_proxy's `/auth` endpoint, which only returns a 202 Accepted response or a 401 Unauthorized response without proxying the request through. For example:

```nginx
server {
  listen 443 ssl;
  server_name ...;
  include ssl/ssl.conf;

  location /oauth2/ {
    proxy_pass       http://127.0.0.1:4180;
    proxy_set_header Host                    $host;
    proxy_set_header X-Real-IP               $remote_addr;
    proxy_set_header X-Scheme                $scheme;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
  }
  location = /oauth2/auth {
    proxy_pass       http://127.0.0.1:4180;
    proxy_set_header Host             $host;
    proxy_set_header X-Real-IP        $remote_addr;
    proxy_set_header X-Scheme         $scheme;
    # nginx auth_request includes headers but not body
    proxy_set_header Content-Length   "";
    proxy_pass_request_body           off;
  }

  location / {
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in;

    # pass information via X-User and X-Email headers to backend,
    # requires running with --set-xauthrequest flag
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;

    # if you enabled --cookie-refresh, this is needed for it to work with auth_request
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;

    proxy_pass http://backend/;
    # or "root /path/to/site;" or "fastcgi_pass ..." etc
  }
}
```
