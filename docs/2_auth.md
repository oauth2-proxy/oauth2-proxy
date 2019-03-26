---
layout: default
title: Auth Configuration
permalink: /auth-configuration
nav_order: 2
---

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
