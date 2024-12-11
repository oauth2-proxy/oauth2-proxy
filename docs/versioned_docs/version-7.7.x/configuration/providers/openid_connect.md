---
id: openid_connect
title: OpenID Connect
---

OpenID Connect is a spec for OAUTH 2.0 + identity that is implemented by many major providers and several open source projects.

This provider was originally built against CoreOS Dex, and we will use it as an example.
The OpenID Connect Provider (OIDC) can also be used to connect to other Identity Providers such as Okta, an example can be found below.

#### Dex

To configure the OIDC provider for Dex, perform the following steps:

1. Download Dex:

    ```
    go get github.com/dexidp/dex
    ```

   See the [getting started guide](https://dexidp.io/docs/getting-started/) for more details.

2. Setup oauth2-proxy with the correct provider and using the default ports and callbacks. Add a configuration block to 
   the `staticClients` section of `examples/config-dev.yaml`:

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

    ```shell
    --provider oidc
    --provider-display-name "My OIDC Provider"
    --client-id oauth2-proxy
    --client-secret proxy
    --redirect-url http://127.0.0.1:4180/oauth2/callback
    --oidc-issuer-url http://127.0.0.1:5556/dex
    --cookie-secure=false
    --cookie-secret=secret
    --email-domain kilgore.trout
    ```

   To serve the current working directory as a website under the `/static` endpoint, add:

    ```shell
    --upstream file://$PWD/#/static/
    ```

5. Test the setup by visiting http://127.0.0.1:4180 or http://127.0.0.1:4180/static .

See also [our local testing environment](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/contrib/local-environment) for a self-contained example using Docker and etcd as storage for Dex.

#### Okta

To configure the OIDC provider for Okta, perform the following steps:

1. Log in to Okta using an administrative account. It is suggested you try this in preview first, `example.oktapreview.com`
2. (OPTIONAL) If you want to configure authorization scopes and claims to be passed on to multiple applications,
   you may wish to configure an authorization server for each application. Otherwise, the provided `default` will work.
   * Navigate to **Security** then select **API**
   * Click **Add Authorization Server**, if this option is not available you may require an additional license for a custom 
     authorization server.
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

The `oidc_issuer_url` is based on URL from your **Authorization Server**'s **Issuer** field in step 2, or simply 
https://corp.okta.com. The `client_id` and `client_secret` are configured in the application settings.
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
    ```shell
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
