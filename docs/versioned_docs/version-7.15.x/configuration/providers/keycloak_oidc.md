---
id: keycloak_oidc
title: Keycloak OIDC
---

## Config Options

| Flag             | Toml Field      | Type           | Description                                                                                                        | Default |
| ---------------- | --------------- | -------------- | ------------------------------------------------------------------------------------------------------------------ | ------- |
| `--allowed-role` | `allowed_roles` | string \| list | restrict logins to users with this role (may be given multiple times). Only works with the keycloak-oidc provider. |         |

## Usage

```
    --provider=keycloak-oidc
    --client-id=<your client's id>
    --client-secret=<your client's secret>
    --redirect-url=https://internal.yourcompany.com/oauth2/callback
    --oidc-issuer-url=https://<keycloak host>/realms/<your realm> // For Keycloak versions <17: --oidc-issuer-url=https://<keycloak host>/auth/realms/<your realm>
    --email-domain=<yourcompany.com> // Validate email domain for users, see option documentation
    --allowed-role=<realm role name> // Optional, required realm role
    --allowed-role=<client id>:<client role name> // Optional, required client role
    --allowed-group=</group name> // Optional, requires group client scope
    --code-challenge-method=S256 // PKCE
```

:::note
Keycloak has updated its admin console and as of version 19.0.0, the new admin console is enabled by default. The 
legacy admin console has been announced for removal with the release of version 21.0.0.
:::

**Keycloak legacy admin console**

1.  Create new client in your Keycloak realm with **Access Type** 'confidential', **Client protocol**  'openid-connect' 
    and **Valid Redirect URIs** 'https://internal.yourcompany.com/oauth2/callback'
2.  Take note of the Secret in the credential tab of the client
3.  Create a mapper with **Mapper Type** 'Group Membership' and **Token Claim Name** 'groups'.
4.  Create a mapper with **Mapper Type** 'Audience' and **Included Client Audience** and **Included Custom Audience** set 
    to your client name.

**Keycloak new admin console (default as of v19.0.0)**

The following example shows how to create a simple OIDC client using the new Keycloak admin2 console. However, for best 
practices, it is recommended to consult the Keycloak documentation.

The OIDC client must be configured with an _audience mapper_ to include the client's name in the `aud` claim of the JWT token.  
The `aud` claim specifies the intended recipient of the token, and OAuth2 Proxy expects a match against the values of 
either `--client-id` or `--oidc-extra-audience`.

_In Keycloak, claims are added to JWT tokens through the use of mappers at either the realm level using "client scopes" or 
through "dedicated" client mappers._

**Creating the client**

1. Create a new OIDC client in your Keycloak realm by navigating to:  
   **Clients** -> **Create client**
   * **Client Type** 'OpenID Connect'
   * **Client ID** `<your client's id>`, please complete the remaining fields as appropriate and click **Next**.
       * **Client authentication** 'On'
       * **Authentication flow**
           * **Standard flow**  'selected'
           * **Direct access grants** 'deselect'
               * _Save the configuration._
       * **Settings / Access settings**:
           * **Valid redirect URIs** `https://internal.yourcompany.com/oauth2/callback`
               * _Save the configuration._
       * Under the **Credentials** tab you will now be able to locate `<your client's secret>`.
2. Configure a dedicated *audience mapper* for your client by navigating to **Clients** -> **\<your client's id\>** -> **Client scopes**.
* Access the dedicated mappers pane by clicking **\<your client's id\>-dedicated**, located under *Assigned client scope*.  
  _(It should have a description of "Dedicated scope and mappers for this client")_
    * Click **Configure a new mapper** and select **Audience**
        * **Name** 'aud-mapper-\<your client's id\>'
        * **Included Client Audience** select `<your client's id>` from the dropdown.
            * _OAuth2 proxy can be set up to pass both the access and ID JWT tokens to your upstream services.
              If you require additional audience entries, you can use the **Included Custom Audience** field in addition 
              to the "Included Client Audience" dropdown. Note that the "aud" claim of a JWT token should be limited and 
              only specify its intended recipients._
        * **Add to ID token** 'On'
        * **Add to access token** 'On' - [#1916](https://github.com/oauth2-proxy/oauth2-proxy/pull/1916)
            * _Save the configuration._
* Any subsequent dedicated client mappers can be defined by clicking **Dedicated scopes** -> **Add mapper** -> 
  **By configuration** -> *Select mapper*

You should now be able to create a test user in Keycloak and get access to the OAuth2 Proxy instance, make sure to set 
an email address matching `<yourcompany.com>` and select _Email verified_.

**Authorization**

_OAuth2 Proxy will perform authorization by requiring a valid user, this authorization can be extended to take into 
account a user's membership in Keycloak `groups`, `realm roles`, and `client roles` using the keycloak-oidc provider options   
`--allowed-role` or `--allowed-group`_

**Roles**

_A standard Keycloak installation comes with the required mappers for **realm roles** and **client roles** through the 
pre-defined client scope "roles". This ensures that any roles assigned to a user are included in the `JWT` tokens when 
using an OIDC client that has the "Full scope allowed" feature activated, the feature is enabled by default._

_Creating a realm role_
* Navigate to **Realm roles** -> **Create role**
    * **Role name**, *`<realm role name>`* -> **save**

_Creating a client role_
* Navigate to **Clients** -> `<your client's id>` -> **Roles** -> **Create role**
    * **Role name**, *`<client role name>`* -> **save**


_Assign a role to a user_

**Users** -> _Username_ -> **Role mapping** -> **Assign role** -> _filter by roles or clients and select_ -> **Assign**.

Keycloak "realm roles" can be authorized using the `--allowed-role=<realm role name>` option, while "client roles" can be 
evaluated using `--allowed-role=<your client's id>:<client role name>`.

You may limit the _realm roles_ included in the JWT tokens for any given client by navigating to:  
**Clients** -> `<your client's id>` -> **Client scopes** ->  _\<your client's id\>-dedicated_ -> **Scope**  
Disabling **Full scope allowed** activates the **Assign role** option, allowing you to select which roles, if assigned 
to a user, will be included in the user's JWT tokens. This can be useful when a user has many associated roles, and you 
want to reduce the size and impact of the JWT token.


**Groups**

You may also do authorization on group memberships by using the OAuth2 Proxy option `--allowed-group`.   
We will only do a brief description of creating the required _client scope_ **groups** and refer you to read the Keycloak 
documentation.

To summarize, the steps required to authorize Keycloak group membership with OAuth2 Proxy are as follows:

* Create a new Client Scope with the name **groups** in Keycloak.
    * Include a mapper of type **Group Membership**.
    * Set the "Token Claim Name" to **groups** or customize by matching it to the `--oidc-groups-claim` option of OAuth2 Proxy.
    * If the "Full group path" option is selected, you need to include a "/" separator in the group names defined in the 
      `--allowed-group` option of OAuth2 Proxy. Example: "/groupname" or "/groupname/child_group".

After creating the _Client Scope_ named _groups_ you will need to attach it to your client.  
**Clients** -> `<your client's id>` -> **Client scopes** -> **Add client scope** -> Select **groups** and choose Optional 
and you should now have a client that maps group memberships into the JWT tokens so that Oauth2 Proxy may evaluate them.

Create a group by navigating to **Groups** -> **Create group** and _add_ your test user as a member.

The OAuth2 Proxy option `--allowed-group=/groupname` will now allow you to filter on group membership

Keycloak also has the option of attaching roles to groups, please refer to the Keycloak documentation for more information.

**Tip**

To check if roles or groups are added to JWT tokens, you can preview a users token in the Keycloak console by following 
these steps: **Clients** -> `<your client's id>` -> **Client scopes** -> **Evaluate**.  
Select a _realm user_ and optional _scope parameters_ such as groups, and generate the JSON representation of an access 
or id token to examine its contents.
