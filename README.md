# oauth2_proxy

A reverse proxy and static file server that provides authentication using Providers (Google, GitHub, and others)
to validate accounts by email, domain or group.

**Note:** This repository was forked from [bitly/OAuth2_Proxy](https://github.com/bitly/oauth2_proxy) on 27/11/2018.
Versions v3.0.0 and up are from this fork and will have diverged from any changes in the original fork.
A list of changes can be seen in the [CHANGELOG](CHANGELOG.md).

[![Build Status](https://secure.travis-ci.org/pusher/oauth2_proxy.svg?branch=master)](http://travis-ci.org/pusher/oauth2_proxy)

![Sign In Page](https://cloud.githubusercontent.com/assets/45028/4970624/7feb7dd8-6886-11e4-93e0-c9904af44ea8.png)

## Architecture

![OAuth2 Proxy Architecture](https://cloud.githubusercontent.com/assets/45028/8027702/bd040b7a-0d6a-11e5-85b9-f8d953d04f39.png)

## Installation

1.  Choose how to deploy:

    a. Download [Prebuilt Binary](https://github.com/pusher/oauth2_proxy/releases) (current release is `v3.2.0`)

    b. Build with `$ go get github.com/pusher/oauth2_proxy` which will put the binary in `$GOROOT/bin`

    c. Using the prebuilt docker image [quay.io/pusher/oauth2_proxy](https://quay.io/pusher/oauth2_proxy) (AMD64, ARMv6 and ARM64 tags available)

Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.

```
sha256sum -c sha256sum.txt 2>&1 | grep OK
oauth2_proxy-3.2.0.linux-amd64: OK
```

2.  Select a Provider and Register an OAuth Application with a Provider
3.  Configure OAuth2 Proxy using config file, command line options, or environment variables
4.  Configure SSL or Deploy behind a SSL endpoint (example provided for Nginx)

## OAuth Provider Configuration

You will need to register an OAuth application with a Provider (Google, GitHub or another provider), and configure it with Redirect URI(s) for the domain you intend to run `oauth2_proxy` on.

Valid providers are :

- [Google](#google-auth-provider) _default_
- [Azure](#azure-auth-provider)
- [Facebook](#facebook-auth-provider)
- [GitHub](#github-auth-provider)
- [GitLab](#gitlab-auth-provider)
- [LinkedIn](#linkedin-auth-provider)
- [login.gov](#logingov-provider)

The provider can be selected using the `provider` configuration value.

### Google Auth Provider

For Google, the registration steps are:

1.  Create a new project: https://console.developers.google.com/project
2.  Choose the new project from the top right project dropdown (only if another project is selected)
3.  In the project Dashboard center pane, choose **"API Manager"**
4.  In the left Nav pane, choose **"Credentials"**
5.  In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
6.  In the center pane, choose **"Credentials"** tab.
    - Open the **"New credentials"** drop down
    - Choose **"OAuth client ID"**
    - Choose **"Web application"**
    - Application name is freeform, choose something appropriate
    - Authorized JavaScript origins is your domain ex: `https://internal.yourcompany.com`
    - Authorized redirect URIs is the location of oauth2/callback ex: `https://internal.yourcompany.com/oauth2/callback`
    - Choose **"Create"**
7.  Take note of the **Client ID** and **Client Secret**

It's recommended to refresh sessions on a short interval (1h) with `cookie-refresh` setting which validates that the account is still authorized.

#### Restrict auth to specific Google groups on your domain. (optional)

1.  Create a service account: https://developers.google.com/identity/protocols/OAuth2ServiceAccount and make sure to download the json file.
2.  Make note of the Client ID for a future step.
3.  Under "APIs & Auth", choose APIs.
4.  Click on Admin SDK and then Enable API.
5.  Follow the steps on https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account and give the client id from step 2 the following oauth scopes:

```
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.user.readonly
```

6.  Follow the steps on https://support.google.com/a/answer/60757 to enable Admin API access.
7.  Create or choose an existing administrative email address on the Gmail domain to assign to the `google-admin-email` flag. This email will be impersonated by this client to make calls to the Admin SDK. See the note on the link from step 5 for the reason why.
8.  Create or choose an existing email group and set that email to the `google-group` flag. You can pass multiple instances of this flag with different groups
    and the user will be checked against all the provided groups.
9.  Lock down the permissions on the json file downloaded from step 1 so only oauth2_proxy is able to read the file and set the path to the file in the `google-service-account-json` flag.
10. Restart oauth2_proxy.

Note: The user is checked against the group members list on initial authentication and every time the token is refreshed ( about once an hour ).

### Azure Auth Provider

1. Add an application: go to [https://portal.azure.com](https://portal.azure.com), choose **"Azure Active Directory"** in the left menu, select **"App registrations"** and then click on **"New app registration"**.
2. Pick a name and choose **"Webapp / API"** as application type. Use `https://internal.yourcompany.com` as Sign-on URL. Click **"Create"**.
3. On the **"Settings"** / **"Properties"** page of the app, pick a logo and select **"Multi-tenanted"** if you want to allow users from multiple organizations to access your app. Note down the application ID. Click **"Save"**.
4. On the **"Settings"** / **"Required Permissions"** page of the app, click on **"Windows Azure Active Directory"** and then on **"Access the directory as the signed in user"**. Hit **"Save"** and then then on **"Grant permissions"** (you might need another admin to do this).
5. On the **"Settings"** / **"Reply URLs"** page of the app, add `https://internal.yourcompanycom/oauth2/callback` for each host that you want to protect by the oauth2 proxy. Click **"Save"**.
6. On the **"Settings"** / **"Keys"** page of the app, add a new key and note down the value after hitting **"Save"**.
7. Configure the proxy with

```
   --provider=azure
   --client-id=<application ID from step 3>
   --client-secret=<value from step 6>
```

### Facebook Auth Provider

1.  Create a new FB App from <https://developers.facebook.com/>
2.  Under FB Login, set your Valid OAuth redirect URIs to `https://internal.yourcompany.com/oauth2/callback`

### GitHub Auth Provider

1.  Create a new project: https://github.com/settings/developers
2.  Under `Authorization callback URL` enter the correct url ie `https://internal.yourcompany.com/oauth2/callback`

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

1.  Create a new project: https://www.linkedin.com/secure/developer
2.  In the OAuth User Agreement section:
    - In default scope, select r_basicprofile and r_emailaddress.
    - In "OAuth 2.0 Redirect URLs", enter `https://internal.yourcompany.com/oauth2/callback`
3.  Fill in the remaining required fields and Save.
4.  Take note of the **Consumer Key / API Key** and **Consumer Secret / Secret Key**

### Microsoft Azure AD Provider

For adding an application to the Microsoft Azure AD follow [these steps to add an application](https://azure.microsoft.com/en-us/documentation/articles/active-directory-integrating-applications/).

Take note of your `TenantId` if applicable for your situation. The `TenantId` can be used to override the default `common` authorization server with a tenant specific server.

### OpenID Connect Provider

OpenID Connect is a spec for OAUTH 2.0 + identity that is implemented by many major providers and several open source projects. This provider was originally built against CoreOS Dex and we will use it as an example.

1.  Launch a Dex instance using the [getting started guide](https://github.com/coreos/dex/blob/master/Documentation/getting-started.md).
2.  Setup oauth2_proxy with the correct provider and using the default ports and callbacks.
3.  Login with the fixture use in the dex guide and run the oauth2_proxy with the following args:

    -provider oidc
    -client-id oauth2_proxy
    -client-secret proxy
    -redirect-url http://127.0.0.1:4180/oauth2/callback
    -oidc-issuer-url http://127.0.0.1:5556
    -cookie-secure=false
    -email-domain example.com

### login.gov Provider

login.gov is an OIDC provider for the US Government.
If you are a US Government agency, you can contact the login.gov team through the contact information
that you can find on https://login.gov/developers/ and work with them to understand how to get login.gov
accounts for integration/test and production access.

A developer guide is available here: https://developers.login.gov/, though this proxy handles everything
but the data you need to create to register your application in the login.gov dashboard.

As a demo, we will assume that you are running your application that you want to secure locally on
http://localhost:3000/, that you will be starting your proxy up on http://localhost:4180/, and that
you have an agency integration account for testing.

First, register your application in the dashboard.  The important bits are:
  * Identity protocol:  make this `Openid connect`
  * Issuer:  do what they say for OpenID Connect.  We will refer to this string as `${LOGINGOV_ISSUER}`.
  * Public key:  This is a self-signed certificate in .pem format generated from a 2048 bit RSA private key.
    A quick way to do this is `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj '/C=US/ST=Washington/L=DC/O=GSA/OU=18F/CN=localhost'`,
    The contents of the `key.pem` shall be referred to as `${OAUTH2_PROXY_JWT_KEY}`.
  * Return to App URL:  Make this be `http://localhost:4180/`
  * Redirect URIs:  Make this be `http://localhost:4180/oauth2/callback`.
  * Attribute Bundle:  Make sure that email is selected.

Now start the proxy up with the following options:
```
./oauth2_proxy -provider login.gov \
  -client-id=${LOGINGOV_ISSUER} \
  -redirect-url=http://localhost:4180/oauth2/callback \
  -oidc-issuer-url=https://idp.int.identitysandbox.gov/ \
  -cookie-secure=false \
  -email-domain=gsa.gov \
  -upstream=http://localhost:3000/ \
  -cookie-secret=somerandomstring12341234567890AB \
  -cookie-domain=localhost \
  -skip-provider-button=true \
  -pubjwk-url=https://idp.int.identitysandbox.gov/api/openid_connect/certs \
  -profile-url=https://idp.int.identitysandbox.gov/api/openid_connect/userinfo \
  -jwt-key="${OAUTH2_PROXY_JWT_KEY}"
```
You can also set all these options with environment variables, for use in cloud/docker environments.
One tricky thing that you may encounter is that some cloud environments will pass in environment
variables in a docker env-file, which does not allow multiline variables like a PEM file.
If you encounter this, then you can create a `jwt_signing_key.pem` file in the top level
directory of the repo which contains the key in PEM format and then do your docker build.
The docker build process will copy that file into your image which you can then access by
setting the `OAUTH2_PROXY_JWT_KEY_FILE=/etc/ssl/private/jwt_signing_key.pem`
environment variable, or by setting `-jwt-key-file=/etc/ssl/private/jwt_signing_key.pem` on the commandline.

Once it is running, you should be able to go to `http://localhost:4180/` in your browser,
get authenticated by the login.gov integration server, and then get proxied on to your
application running on `http://localhost:3000/`.  In a real deployment, you would secure
your application with a firewall or something so that it was only accessible from the
proxy, and you would use real hostnames everywhere.

#### Skip OIDC discovery

Some providers do not support OIDC discovery via their issuer URL, so oauth2_proxy cannot simply grab the authorization, token and jwks URI endpoints from the provider's metadata.

In this case, you can set the `-skip-oidc-discovery` option, and supply those required endpoints manually:

```
    -provider oidc
    -client-id oauth2_proxy
    -client-secret proxy
    -redirect-url http://127.0.0.1:4180/oauth2/callback
    -oidc-issuer-url http://127.0.0.1:5556
    -skip-oidc-discovery
    -login-url http://127.0.0.1:5556/authorize
    -redeem-url http://127.0.0.1:5556/token
    -oidc-jwks-url http://127.0.0.1:5556/keys
    -cookie-secure=false
    -email-domain example.com
```

## Email Authentication

To authorize by email domain use `--email-domain=yourcompany.com`. To authorize individual email addresses use `--authenticated-emails-file=/path/to/file` with one email per line. To authorize all email addresses use `--email-domain=*`.

## Adding a new Provider

Follow the examples in the [`providers` package](providers/) to define a new
`Provider` instance. Add a new `case` to
[`providers.New()`](providers/providers.go) to allow `oauth2_proxy` to use the
new `Provider`.

## Configuration

`oauth2_proxy` can be configured via [config file](#config-file), [command line options](#command-line-options) or [environment variables](#environment-variables).

To generate a strong cookie secret use `python -c 'import os,base64; print base64.urlsafe_b64encode(os.urandom(16))'`

### Config File

An example [oauth2_proxy.cfg](contrib/oauth2_proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `-config=/etc/oauth2_proxy.cfg`

### Command Line Options

```
Usage of oauth2_proxy:
  -acr-values string:  optional, used by login.gov (default "http://idmanagement.gov/ns/assurance/loa/1")
  -approval-prompt string: OAuth approval_prompt (default "force")
  -auth-logging: Log authentication attempts (default true)
  -auth-logging-format string: Template for authentication log lines (see "Logging Configuration" paragraph below)
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
  -cookie-path string: an optional cookie path to force cookies to (ie: /poc/)* (default "/")
  -cookie-refresh duration: refresh the cookie after this duration; 0 to disable
  -cookie-secret string: the seed string for secure cookies (optionally base64 encoded)
  -cookie-secure: set secure (HTTPS) cookie flag (default true)
  -custom-templates-dir string: path to custom html templates
  -display-htpasswd-form: display username / password login form if an htpasswd file is provided (default true)
  -email-domain value: authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email
  -flush-interval: period between flushing response buffers when streaming responses (default "1s")
  -footer string: custom footer string. Use "-" to disable default footer.
  -gcp-healthchecks: will enable /liveness_check, /readiness_check, and / (with the proper user-agent) endpoints that will make it work well with GCP App Engine and GKE Ingresses (default false)
  -github-org string: restrict logins to members of this organisation
  -github-team string: restrict logins to members of any of these teams (slug), separated by a comma
  -google-admin-email string: the google admin to impersonate for api calls
  -google-group value: restrict logins to members of this google group (may be given multiple times).
  -google-service-account-json string: the path to the service account json credentials
  -htpasswd-file string: additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address string: [http://]<addr>:<port> or unix://<path> to listen on for HTTP clients (default "127.0.0.1:4180")
  -https-address string: <addr>:<port> to listen on for HTTPS clients (default ":443")
  -logging-compress: Should rotated log files be compressed using gzip (default false)
  -logging-filename string: File to log requests to, empty for stdout (default to stdout)
  -logging-local-time: If the time in log files and backup filenames are local or UTC time (default true)
  -logging-max-age int: Maximum number of days to retain old log files (default 7)
  -logging-max-backups int: Maximum number of old log files to retain; 0 to disable (default 0)
  -logging-max-size int: Maximum size in megabytes of the log file before rotation (default 100)
  -jwt-key string: private key in PEM format used to sign JWT, so that you can say something like -jwt-key="${OAUTH2_PROXY_JWT_KEY}": required by login.gov
  -jwt-key-file string: path to the private key file in PEM format used to sign the JWT so that you can say something like -jwt-key-file=/etc/ssl/private/jwt_signing_key.pem: required by login.gov
  -login-url string: Authentication endpoint
  -oidc-issuer-url: the OpenID Connect issuer URL. ie: "https://accounts.google.com"
  -oidc-jwks-url string: OIDC JWKS URI for token verification; required if OIDC discovery is disabled
  -pass-access-token: pass OAuth access_token to upstream via X-Forwarded-Access-Token header
  -pass-authorization-header: pass OIDC IDToken to upstream via Authorization Bearer header
  -pass-basic-auth: pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -pass-host-header: pass the request Host Header to upstream (default true)
  -pass-user-headers: pass X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -profile-url string: Profile access endpoint
  -provider string: OAuth provider (default "google")
  -proxy-prefix string: the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in) (default "/oauth2")
  -proxy-websockets: enables WebSocket proxying (default true)
  -pubjwk-url string: JWK pubkey access endpoint: required by login.gov
  -redeem-url string: Token redemption endpoint
  -redirect-url string: the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -request-logging: Log requests to stdout (default true)
  -request-logging-format: Template for request log lines (see "Logging Configuration" paragraph below)
  -resource string: The resource that is protected (Azure AD only)
  -scope string: OAuth scope specification
  -set-xauthrequest: set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)
  -set-authorization-header: set Authorization Bearer response header (useful in Nginx auth_request mode)
  -signature-key string: GAP-Signature request signature key (algorithm:secretkey)
  -skip-auth-preflight: will skip authentication for OPTIONS requests
  -skip-auth-regex value: bypass authentication for requests path's that match (may be given multiple times)
  -skip-oidc-discovery: bypass OIDC endpoint discovery. login-url, redeem-url and oidc-jwks-url must be configured in this case
  -skip-provider-button: will skip sign-in-page to directly reach the next step: oauth/start
  -ssl-insecure-skip-verify: skip validation of certificates presented when using HTTPS
  -standard-logging: Log standard runtime information (default true)
  -standard-logging-format string: Template for standard log lines (see "Logging Configuration" paragraph below)
  -tls-cert string: path to certificate file
  -tls-key string: path to private key file
  -upstream value: the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path
  -validate-url string: Access token validation endpoint
  -version: print version string
  -whitelist-domain: allowed domains for redirection after authentication. Prefix domain with a . to allow subdomains (eg .example.com)
```

Note, when using the `whitelist-domain` option, any domain prefixed with a `.` will allow any subdomain of the specified domain as a valid redirect URL.

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
- `OAUTH2_PROXY_COOKIE_PATH`
- `OAUTH2_PROXY_COOKIE_EXPIRE`
- `OAUTH2_PROXY_COOKIE_REFRESH`
- `OAUTH2_PROXY_SIGNATURE_KEY`

## Logging Configuration

By default, OAuth2 Proxy logs all output to stdout. Logging can be configured to output to a rotating log file using the `-logging-filename` command.

If logging to a file you can also configure the maximum file size (`-logging-max-size`), age (`-logging-max-age`), max backup logs (`-logging-max-backups`), and if backup logs should be compressed (`-logging-compress`).

There are three different types of logging: standard, authentication, and HTTP requests. These can each be enabled or disabled with `-standard-logging`, `-auth-logging`, and `-request-logging`.

Each type of logging has their own configurable format and variables. By default these formats are similar to the Apache Combined Log.

### Auth Log Format
Authentication logs are logs which are guaranteed to contain a username or email address of a user attempting to authenticate. These logs are output by default in the below format:

```
<REMOTE_ADDRESS> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] [<STATUS>] <MESSAGE>
```

The status block will contain one of the below strings:

- `AuthSuccess` If a user has authenticated successfully by any method
- `AuthFailure` If the user failed to authenticate explicitly
- `AuthError` If there was an unexpected error during authentication

If you require a different format than that, you can configure it with the `-auth-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}
```

Available variables for auth logging:

| Variable | Example | Description |
| --- | --- | --- |
| Client | 74.125.224.72 | The client/remote IP address. Will use the X-Real-IP header it if exists. |
| Host  | domain.com | The value of the Host header. |
| Protocol | HTTP/1.0 | The request protocol. |
| RequestMethod | GET | The request method. |
| Timestamp | 19/Mar/2015:17:20:19 -0400 | The date and time of the logging event. |
| UserAgent | - | The full user agent as reported by the requesting client. |
| Username | username@email.com | The email or username of the auth request. |
| Status | AuthSuccess | The status of the auth request. See above for details. |
| Message | Authenticated via OAuth2 | The details of the auth attempt. |

### Request Log Format
HTTP request logs will output by default in the below format:

```
<REMOTE_ADDRESS> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

If you require a different format than that, you can configure it with the `-request-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}
```

Available variables for request logging:

| Variable | Example | Description |
| --- | --- | --- |
| Client | 74.125.224.72 | The client/remote IP address. Will use the X-Real-IP header it if exists. |
| Host  | domain.com | The value of the Host header. |
| Protocol | HTTP/1.0 | The request protocol. |
| RequestDuration | 0.001 | The time in seconds that a request took to process. |
| RequestMethod | GET | The request method. |
| RequestURI | "/oauth2/auth" | The URI path of the request. |
| ResponseSize | 12 | The size in bytes of the response. |
| StatusCode | 200 | The HTTP status code of the response. |
| Timestamp | 19/Mar/2015:17:20:19 -0400 | The date and time of the logging event. |
| Upstream | - | The upstream data of the HTTP request. |
| UserAgent | - | The full user agent as reported by the requesting client. |
| Username | username@email.com | The email or username of the auth request. |

### Standard Log Format
All other logging that is not covered by the above two types of logging will be output in this standard logging format. This includes configuration information at startup and errors that occur outside of a session. The default format is below:

```
[19/Mar/2015:17:20:19 -0400] [main.go:40] <MESSAGE>
```

If you require a different format than that, you can configure it with the `-standard-logging-format` flag. The default format is configured as follows:

```
[{{.Timestamp}}] [{{.File}}] {{.Message}}
```

Available variables for standard logging:

| Variable | Example | Description |
| --- | --- | --- |
| Timestamp | 19/Mar/2015:17:20:19 -0400 | The date and time of the logging event. |
| File | main.go:40 | The file and line number of the logging statement. |
| Message | HTTP: listening on 127.0.0.1:4180 | The details of the log statement. |

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

If you use ingress-nginx in Kubernetes (which includes the Lua module), you also can use the following configuration snippet for your Ingress:

```yaml
nginx.ingress.kubernetes.io/auth-response-headers: Authorization
nginx.ingress.kubernetes.io/auth-signin: https://$host/oauth2/start?rd=$request_uri
nginx.ingress.kubernetes.io/auth-url: https://$host/oauth2/auth
nginx.ingress.kubernetes.io/configuration-snippet: |
  auth_request_set $name_upstream_1 $upstream_cookie_name_1;

  access_by_lua_block {
    if ngx.var.name_upstream_1 ~= "" then
      ngx.header["Set-Cookie"] = "name_1=" .. ngx.var.name_upstream_1 .. ngx.var.auth_cookie:match("(; .*)")
    end
  }
```

## SSL Configuration

There are two recommended configurations.

1.  Configure SSL Termination with OAuth2 Proxy by providing a `--tls-cert=/path/to/cert.pem` and `--tls-key=/path/to/cert.key`.

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

2.  Configure SSL Termination with [Nginx](http://nginx.org/) (example config below), Amazon ELB, Google Cloud Platform Load Balancing, or ....

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

- /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
- /ping - returns a 200 OK response, which is intended for use with health checks
- /oauth2/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
- /oauth2/start - a URL that will redirect to start the OAuth cycle
- /oauth2/callback - the URL used at the end of the OAuth cycle. The oauth app will be configured with this as the callback url.
- /oauth2/auth - only returns a 202 Accepted response or a 401 Unauthorized response; for use with the [Nginx `auth_request` directive](#nginx-auth-request)

## Request signatures

If `signature_key` is defined, proxied requests will be signed with the
`GAP-Signature` header, which is a [Hash-based Message Authentication Code
(HMAC)](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
of selected request information and the request body [see `SIGNATURE_HEADERS`
in `oauthproxy.go`](./oauthproxy.go).

`signature_key` must be of the form `algorithm:secretkey`, (ie: `signature_key = "sha1:secret0"`)

For more information about HMAC request signature validation, read the
following:

- [Amazon Web Services: Signing and Authenticating REST
  Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
- [rc3.org: Using HMAC to authenticate Web service
  requests](http://rc3.org/2011/12/02/using-hmac-to-authenticate-web-service-requests/)

## Contributing

Please see our [Contributing](CONTRIBUTING.md) guidelines.
