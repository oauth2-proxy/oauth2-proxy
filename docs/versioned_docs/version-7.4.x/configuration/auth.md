---
id: oauth_provider
title: OAuth Provider Configuration
---

You will need to register an OAuth application with a Provider (Google, GitHub or another provider), and configure it with Redirect URI(s) for the domain you intend to run `oauth2-proxy` on.

Valid providers are :

- [Google](#google-auth-provider) _default_
- [Azure](#azure-auth-provider)
- [ADFS](#adfs-auth-provider)
- [Facebook](#facebook-auth-provider)
- [GitHub](#github-auth-provider)
- [Keycloak](#keycloak-auth-provider)
- [GitLab](#gitlab-auth-provider)
- [LinkedIn](#linkedin-auth-provider)
- [Microsoft Azure AD](#microsoft-azure-ad-provider)
- [OpenID Connect](#openid-connect-provider)
- [login.gov](#logingov-provider)
- [Nextcloud](#nextcloud-provider)
- [DigitalOcean](#digitalocean-auth-provider)
- [Bitbucket](#bitbucket-auth-provider)
- [Gitea](#gitea-auth-provider)

The provider can be selected using the `provider` configuration value.

Please note that not all providers support all claims. The `preferred_username` claim is currently only supported by the OpenID Connect provider.

### Google Auth Provider

For Google, the registration steps are:

1.  Create a new project: https://console.developers.google.com/project
2.  Choose the new project from the top right project dropdown (only if another project is selected)
3.  In the project Dashboard center pane, choose **"APIs & Services"**
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
9.  Lock down the permissions on the json file downloaded from step 1 so only oauth2-proxy is able to read the file and set the path to the file in the `google-service-account-json` flag.
10. Restart oauth2-proxy.

Note: The user is checked against the group members list on initial authentication and every time the token is refreshed ( about once an hour ).

### Azure Auth Provider

1. Add an application: go to [https://portal.azure.com](https://portal.azure.com), choose **Azure Active Directory**, select 
**App registrations** and then click on **New registration**.
2. Pick a name, check the supported account type(single-tenant, multi-tenant, etc). In the **Redirect URI** section create a new 
**Web** platform entry for each app that you want to protect by the oauth2 proxy(e.g. 
https://internal.yourcompanycom/oauth2/callback). Click **Register**.
3. Next we need to add group read permissions for the app registration, on the **API Permissions** page of the app, click on
**Add a permission**, select **Microsoft Graph**, then select **Application permissions**, then click on **Group** and select
**Group.Read.All**. Hit **Add permissions** and then on **Grant admin consent** (you might need an admin to do this).
<br/>**IMPORTANT**: Even if this permission is listed with **"Admin consent required=No"** the consent might actually be required, due to AAD policies you won't be able to see. If you get a **"Need admin approval"** during login, most likely this is what you're missing!
4. Next, if you are planning to use v2.0 Azure Auth endpoint, go to the **Manifest** page and set `"accessTokenAcceptedVersion": 2`
in the App registration manifest file.
5. On the **Certificates & secrets** page of the app, add a new client secret and note down the value after hitting **Add**.
6. Configure the proxy with:
- for V1 Azure Auth endpoint (Azure Active Directory Endpoints - https://login.microsoftonline.com/common/oauth2/authorize)

```
   --provider=azure
   --client-id=<application ID from step 3>
   --client-secret=<value from step 5>
   --azure-tenant={tenant-id}
   --oidc-issuer-url=https://sts.windows.net/{tenant-id}/
```

- for V2 Azure Auth endpoint (Microsoft Identity Platform Endpoints - https://login.microsoftonline.com/common/oauth2/v2.0/authorize)
```
   --provider=azure
   --client-id=<application ID from step 3>
   --client-secret=<value from step 5>
   --azure-tenant={tenant-id}
   --oidc-issuer-url=https://login.microsoftonline.com/{tenant-id}/v2.0
```

***Notes***:
- When using v2.0 Azure Auth endpoint (`https://login.microsoftonline.com/{tenant-id}/v2.0`) as `--oidc_issuer_url`, in conjunction 
with `--resource` flag, be sure to append `/.default` at the end of the resource name. See
https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#the-default-scope for more details.
- When using the Azure Auth provider with nginx and the cookie session store you may find the cookie is too large and doesn't 
get passed through correctly. Increasing the proxy_buffer_size in nginx or implementing the [redis session storage](sessions.md#redis-storage) 
should resolve this.

### ADFS Auth Provider

1. Open the ADFS administration console on your Windows Server and add a new Application Group
2. Provide a name for the integration, select Server Application from the Standalone applications section and click Next
3. Follow the wizard to get the client-id, client-secret and configure the application credentials
4. Configure the proxy with

```
   --provider=adfs
   --client-id=<application ID from step 3>
   --client-secret=<value from step 3>
```

Note: When using the ADFS Auth provider with nginx and the cookie session store you may find the cookie is too large and doesn't get passed through correctly. Increasing the proxy_buffer_size in nginx or implementing the [redis session storage](sessions.md#redis-storage) should resolve this.

### Facebook Auth Provider

1.  Create a new FB App from https://developers.facebook.com/
2.  Under FB Login, set your Valid OAuth redirect URIs to `https://internal.yourcompany.com/oauth2/callback`

### GitHub Auth Provider

1.  Create a new project: https://github.com/settings/developers
2.  Under `Authorization callback URL` enter the correct url ie `https://internal.yourcompany.com/oauth2/callback`

The GitHub auth provider supports two additional ways to restrict authentication to either organization and optional team level access, or to collaborators of a repository. Restricting by these options is normally accompanied with `--email-domain=*`

NOTE: When `--github-user` is set, the specified users are allowed to login even if they do not belong to the specified org and team or collaborators.

To restrict by organization only, include the following flag:

```
    --github-org="": restrict logins to members of this organisation
```

To restrict within an organization to specific teams, include the following flag in addition to `-github-org`:

```
    --github-team="": restrict logins to members of any of these teams (slug), separated by a comma
```

If you would rather restrict access to collaborators of a repository, those users must either have push access to a public repository or any access to a private repository:

```
    --github-repo="": restrict logins to collaborators of this repository formatted as orgname/repo
```

If you'd like to allow access to users with **read only** access to a **public** repository you will need to provide a [token](https://github.com/settings/tokens) for a user that has write access to the repository. The token must be created with at least the `public_repo` scope:

```
    --github-token="": the token to use when verifying repository collaborators
```

To allow a user to login with their username even if they do not belong to the specified org and team or collaborators, separated by a comma

```
    --github-user="": allow logins by username, separated by a comma
```

If you are using GitHub enterprise, make sure you set the following to the appropriate url:

```
    --login-url="http(s)://<enterprise github host>/login/oauth/authorize"
    --redeem-url="http(s)://<enterprise github host>/login/oauth/access_token"
    --validate-url="http(s)://<enterprise github host>/api/v3"
```

### Keycloak Auth Provider

:::note 
This is the legacy provider for Keycloak, use [Keycloak OIDC Auth Provider](#keycloak-oidc-auth-provider) if possible.
:::

1.  Create new client in your Keycloak realm with **Access Type** 'confidental' and **Valid Redirect URIs** 'https://internal.yourcompany.com/oauth2/callback'
2.  Take note of the Secret in the credential tab of the client
3.  Create a mapper with **Mapper Type** 'Group Membership' and **Token Claim Name** 'groups'.

Make sure you set the following to the appropriate url:

```
    --provider=keycloak
    --client-id=<client you have created>
    --client-secret=<your client's secret>
    --login-url="http(s)://<keycloak host>/auth/realms/<your realm>/protocol/openid-connect/auth"
    --redeem-url="http(s)://<keycloak host>/auth/realms/<your realm>/protocol/openid-connect/token"
    --profile-url="http(s)://<keycloak host>/auth/realms/<your realm>/protocol/openid-connect/userinfo"
    --validate-url="http(s)://<keycloak host>/auth/realms/<your realm>/protocol/openid-connect/userinfo"
    --keycloak-group=<first_allowed_user_group>
    --keycloak-group=<second_allowed_user_group>
```
    
For group based authorization, the optional `--keycloak-group` (legacy) or `--allowed-group` (global standard)
flags can be used to specify which groups to limit access to.

If these are unset but a `groups` mapper is set up above in step (3), the provider will still
populate the `X-Forwarded-Groups` header to your upstream server with the `groups` data in the
Keycloak userinfo endpoint response.

The group management in keycloak is using a tree. If you create a group named admin in keycloak
you should define the 'keycloak-group' value to /admin.

### Keycloak OIDC Auth Provider

1.  Create new client in your Keycloak realm with **Access Type** 'confidental', **Client protocol**  'openid-connect' and **Valid Redirect URIs** 'https://internal.yourcompany.com/oauth2/callback'
2.  Take note of the Secret in the credential tab of the client
3.  Create a mapper with **Mapper Type** 'Group Membership' and **Token Claim Name** 'groups'.
4.  Create a mapper with **Mapper Type** 'Audience' and **Included Client Audience** and **Included Custom Audience** set to your client name.

Make sure you set the following to the appropriate url:

```
    --provider=keycloak-oidc
    --client-id=<your client's id>
    --client-secret=<your client's secret>
    --redirect-url=https://myapp.com/oauth2/callback
    --oidc-issuer-url=https://<keycloak host>/auth/realms/<your realm>
    --allowed-role=<realm role name> // Optional, required realm role
    --allowed-role=<client id>:<client role name> // Optional, required client role
```

### GitLab Auth Provider

This auth provider has been tested against Gitlab version 12.X. Due to Gitlab API changes, it may not work for version prior to 12.X (see [994](https://github.com/oauth2-proxy/oauth2-proxy/issues/994)).

Whether you are using GitLab.com or self-hosting GitLab, follow [these steps to add an application](https://docs.gitlab.com/ce/integration/oauth_provider.html). Make sure to enable at least the `openid`, `profile` and `email` scopes, and set the redirect url to your application url e.g. https://myapp.com/oauth2/callback.

If you need projects filtering, add the extra `read_api` scope to your application.

The following config should be set to ensure that the oauth will work properly. To get a cookie secret follow [these steps](./overview.md#generating-a-cookie-secret)

```
    --provider="gitlab"
    --redirect-url="https://myapp.com/oauth2/callback" // Should be the same as the redirect url for the application in gitlab
    --client-id=GITLAB_CLIENT_ID
    --client-secret=GITLAB_CLIENT_SECRET
    --cookie-secret=COOKIE_SECRET
```

Restricting by group membership is possible with the following option:

```
    --gitlab-group="mygroup,myothergroup": restrict logins to members of any of these groups (slug), separated by a comma
```

If you are using self-hosted GitLab, make sure you set the following to the appropriate URL:

```
    --oidc-issuer-url="<your gitlab url>"
```

If your self-hosted GitLab is on a sub-directory (e.g. domain.tld/gitlab), as opposed to its own sub-domain (e.g. gitlab.domain.tld), you may need to add a redirect from domain.tld/oauth pointing at e.g. domain.tld/gitlab/oauth.

### LinkedIn Auth Provider

For LinkedIn, the registration steps are:

1.  Create a new project: https://www.linkedin.com/secure/developer
2.  In the OAuth User Agreement section:
    - In default scope, select r_basicprofile and r_emailaddress.
    - In "OAuth 2.0 Redirect URLs", enter `https://internal.yourcompany.com/oauth2/callback`
3.  Fill in the remaining required fields and Save.
4.  Take note of the **Consumer Key / API Key** and **Consumer Secret / Secret Key**

### Microsoft Azure AD Provider

For adding an application to the Microsoft Azure AD follow [these steps to add an application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

Take note of your `TenantId` if applicable for your situation. The `TenantId` can be used to override the default `common` authorization server with a tenant specific server.

### OpenID Connect Provider

OpenID Connect is a spec for OAUTH 2.0 + identity that is implemented by many major providers and several open source projects.

This provider was originally built against CoreOS Dex and we will use it as an example.
The OpenID Connect Provider (OIDC) can also be used to connect to other Identity Providers such as Okta, an example can be found below.

#### Dex

To configure the OIDC provider for Dex, perform the following steps:

1. Download Dex:

    ```
    go get github.com/dexidp/dex
    ```

    See the [getting started guide](https://dexidp.io/docs/getting-started/) for more details.

2. Setup oauth2-proxy with the correct provider and using the default ports and callbacks. Add a configuration block to the `staticClients` section of `examples/config-dev.yaml`:

    ```
    - id: oauth2-proxy
    redirectURIs:
    - 'http://127.0.0.1:4180/oauth2/callback'
    name: 'oauth2-proxy'
    secret: proxy
    ```

3. Launch Dex: from `$GOPATH/github.com/dexidp/dex`, run:

    ```
    bin/dex serve examples/config-dev.yaml
    ```

4. In a second terminal, run the oauth2-proxy with the following args:

    ```
    -provider oidc
    -provider-display-name "My OIDC Provider"
    -client-id oauth2-proxy
    -client-secret proxy
    -redirect-url http://127.0.0.1:4180/oauth2/callback
    -oidc-issuer-url http://127.0.0.1:5556/dex
    -cookie-secure=false
    -cookie-secret=secret
    -email-domain kilgore.trout
    ```

    To serve the current working directory as a web site under the `/static` endpoint, add:

    ```
    -upstream file://$PWD/#/static/
    ```

5. Test the setup by visiting http://127.0.0.1:4180 or http://127.0.0.1:4180/static .

See also [our local testing environment](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/contrib/local-environment) for a self-contained example using Docker and etcd as storage for Dex.

#### Okta

To configure the OIDC provider for Okta, perform the following steps:

1. Log in to Okta using an administrative account. It is suggested you try this in preview first, `example.oktapreview.com`
2. (OPTIONAL) If you want to configure authorization scopes and claims to be passed on to multiple applications,
you may wish to configure an authorization server for each application. Otherwise, the provided `default` will work.
* Navigate to **Security** then select **API**
* Click **Add Authorization Server**, if this option is not available you may require an additional license for a custom authorization server.
* Fill out the **Name** with something to describe the application you are protecting. e.g. 'Example App'.
* For **Audience**, pick the URL of the application you wish to protect: https://example.corp.com
* Fill out a **Description**
* Add any **Access Policies** you wish to configure to limit application access.
* The default settings will work for other options.
[See Okta documentation for more information on Authorization Servers](https://developer.okta.com/docs/guides/customize-authz-server/overview/)
3. Navigate to **Applications** then select **Add Application**.
* Select **Web** for the **Platform** setting.
* Select **OpenID Connect** and click **Create**
* Pick an **Application Name** such as `Example App`.
* Set the **Login redirect URI** to `https://example.corp.com`.
* Under **General** set the **Allowed grant types** to `Authorization Code` and `Refresh Token`.
* Leave the rest as default, taking note of the `Client ID` and `Client Secret`.
* Under **Assignments** select the users or groups you wish to access your application.
4. Create a configuration file like the following:

    ```
    provider = "oidc"
    redirect_url = "https://example.corp.com/oauth2/callback"
    oidc_issuer_url = "https://corp.okta.com/oauth2/abCd1234"
    upstreams = [
        "https://example.corp.com"
    ]
    email_domains = [
        "corp.com"
    ]
    client_id = "XXXXX"
    client_secret = "YYYYY"
    pass_access_token = true
    cookie_secret = "ZZZZZ"
    skip_provider_button = true
    ```

The `oidc_issuer_url` is based on URL from your **Authorization Server**'s **Issuer** field in step 2, or simply https://corp.okta.com .
The `client_id` and `client_secret` are configured in the application settings.
Generate a unique `cookie_secret` to encrypt the cookie.

Then you can start the oauth2-proxy with `./oauth2-proxy --config /etc/example.cfg`

#### Okta - localhost

1. Signup for developer account: https://developer.okta.com/signup/
2. Create New `Web` Application: https://$\{your-okta-domain\}/dev/console/apps/new
3. Example Application Settings for localhost:
   * **Name:** My Web App
   * **Base URIs:** http://localhost:4180/
   * **Login redirect URIs:** http://localhost:4180/oauth2/callback
   * **Logout redirect URIs:** http://localhost:4180/
   * **Group assignments:** `Everyone`
   * **Grant type allowed:** `Authorization Code` and `Refresh Token`
4. Make note of the `Client ID` and `Client secret`, they are needed in a future step
5. Make note of the **default** Authorization Server Issuer URI from: https://$\{your-okta-domain\}/admin/oauth2/as
6. Example config file `/etc/localhost.cfg`
    ```
    provider = "oidc"
    redirect_url = "http://localhost:4180/oauth2/callback"
    oidc_issuer_url = "https://$\{your-okta-domain\}/oauth2/default"
    upstreams = [
        "http://0.0.0.0:8080"
    ]
    email_domains = [
        "*"
    ]
    client_id = "XXX"
    client_secret = "YYY"
    pass_access_token = true
    cookie_secret = "ZZZ"
    cookie_secure = false
    skip_provider_button = true
    # Note: use the following for testing within a container
    # http_address = "0.0.0.0:4180"
    ```
7. Then you can start the oauth2-proxy with `./oauth2-proxy --config /etc/localhost.cfg`

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
./oauth2-proxy -provider login.gov \
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
environment variable, or by setting `--jwt-key-file=/etc/ssl/private/jwt_signing_key.pem` on the commandline.

Once it is running, you should be able to go to `http://localhost:4180/` in your browser,
get authenticated by the login.gov integration server, and then get proxied on to your
application running on `http://localhost:3000/`.  In a real deployment, you would secure
your application with a firewall or something so that it was only accessible from the
proxy, and you would use real hostnames everywhere.

#### Skip OIDC discovery

Some providers do not support OIDC discovery via their issuer URL, so oauth2-proxy cannot simply grab the authorization, token and jwks URI endpoints from the provider's metadata.

In this case, you can set the `--skip-oidc-discovery` option, and supply those required endpoints manually:

```
    -provider oidc
    -client-id oauth2-proxy
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

### Nextcloud Provider

The Nextcloud provider allows you to authenticate against users in your
Nextcloud instance.

When you are using the Nextcloud provider, you must specify the urls via
configuration, environment variable, or command line argument. Depending
on whether your Nextcloud instance is using pretty urls your urls may be of the
form `/index.php/apps/oauth2/*` or `/apps/oauth2/*`.

Refer to the [OAuth2
documentation](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/oauth2.html)
to setup the client id and client secret. Your "Redirection URI" will be
`https://internalapp.yourcompany.com/oauth2/callback`.

```
    -provider nextcloud
    -client-id <from nextcloud admin>
    -client-secret <from nextcloud admin>
    -login-url="<your nextcloud url>/index.php/apps/oauth2/authorize"
    -redeem-url="<your nextcloud url>/index.php/apps/oauth2/api/v1/token"
    -validate-url="<your nextcloud url>/ocs/v2.php/cloud/user?format=json"
```

Note: in *all* cases the validate-url will *not* have the `index.php`.

### DigitalOcean Auth Provider

1. [Create a new OAuth application](https://cloud.digitalocean.com/account/api/applications)
    * You can fill in the name, homepage, and description however you wish.
    * In the "Application callback URL" field, enter: `https://oauth-proxy/oauth2/callback`, substituting `oauth2-proxy` with the actual hostname that oauth2-proxy is running on. The URL must match oauth2-proxy's configured redirect URL.
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=digitalocean
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```

 Alternatively, set the equivalent options in the config file. The redirect URL defaults to `https://<requested host header>/oauth2/callback`. If you need to change it, you can use the `--redirect-url` command-line option.

### Bitbucket Auth Provider

1. [Add a new OAuth consumer](https://confluence.atlassian.com/bitbucket/oauth-on-bitbucket-cloud-238027431.html)
    * In "Callback URL" use `https://<oauth2-proxy>/oauth2/callback`, substituting `<oauth2-proxy>` with the actual hostname that oauth2-proxy is running on.
    * In Permissions section select:
        * Account -> Email
        * Team membership -> Read
        * Repositories -> Read
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=bitbucket
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```

The default configuration allows everyone with Bitbucket account to authenticate. To restrict the access to the team members use additional configuration option: `--bitbucket-team=<Team name>`. To restrict the access to only these users who has access to one selected repository use `--bitbucket-repository=<Repository name>`.


### Gitea Auth Provider

1. Create a new application: `https://< your gitea host >/user/settings/applications`
2. Under `Redirect URI` enter the correct URL i.e. `https://<proxied host>/oauth2/callback`
3. Note the Client ID and Client Secret.
4. Pass the following options to the proxy:

```
    --provider="github"
    --redirect-url="https://<proxied host>/oauth2/callback"
    --provider-display-name="Gitea"
    --client-id="< client_id as generated by Gitea >"
    --client-secret="< client_secret as generated by Gitea >"
    --login-url="https://< your gitea host >/login/oauth/authorize"
    --redeem-url="https://< your gitea host >/login/oauth/access_token"
    --validate-url="https://< your gitea host >/api/v1"
```


## Email Authentication

To authorize by email domain use `--email-domain=yourcompany.com`. To authorize individual email addresses use `--authenticated-emails-file=/path/to/file` with one email per line. To authorize all email addresses use `--email-domain=*`.

## Adding a new Provider

Follow the examples in the [`providers` package](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/providers/) to define a new
`Provider` instance. Add a new `case` to
[`providers.New()`](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/providers/providers.go) to allow `oauth2-proxy` to use the
new `Provider`.
