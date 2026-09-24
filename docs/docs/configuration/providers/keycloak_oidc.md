---
id: keycloak_oidc
title: Keycloak OIDC
---

Use the Keycloak OIDC provider for new Keycloak deployments. The legacy [`keycloak`](keycloak.md) provider is deprecated and should only be used for existing installations that cannot migrate yet.

## Config Options

| Flag             | Toml Field      | Type           | Description                                                                                                        | Default |
| ---------------- | --------------- | -------------- | ------------------------------------------------------------------------------------------------------------------ | ------- |
| `--allowed-role` | `allowed_roles` | string \| list | Restrict logins to users with this role (may be given multiple times). Only works with the `keycloak-oidc` provider. |         |

## Quick start

Create a confidential OpenID Connect client in the Keycloak realm you want to protect and configure OAuth2 Proxy with the issuer URL for that realm.

```shell
--provider=keycloak-oidc
--client-id=<client-id>
--client-secret=<client-secret>
--redirect-url=https://oauth2-proxy.example.com/oauth2/callback
--oidc-issuer-url=https://<keycloak-host>/realms/<realm>
--email-domain=example.com
--code-challenge-method=S256
```

For Keycloak versions earlier than 17, include the legacy `/auth` path in the issuer URL:

```shell
--oidc-issuer-url=https://<keycloak-host>/auth/realms/<realm>
```

Optional authorization examples:

```shell
--allowed-role=<realm-role-name>
--allowed-role=<client-id>:<client-role-name>
--allowed-group=/engineering/platform
```

:::tip
If Keycloak is behind a reverse proxy, make sure Keycloak's configured hostname and proxy headers produce the same issuer URL that OAuth2 Proxy uses in `--oidc-issuer-url`. Issuer mismatches commonly happen when Keycloak advertises an internal host, the wrong scheme, or the wrong context path in its OIDC discovery document.
:::

## Keycloak client setup

In the Keycloak admin console:

1. Go to **Clients** -> **Create client**.
2. Set **Client type** to **OpenID Connect**.
3. Set **Client ID** to the value you will use as `--client-id`.
4. Enable **Client authentication**.
5. Enable **Standard flow**.
6. Disable **Direct access grants** unless another integration requires them.
7. Add the OAuth2 Proxy callback as a valid redirect URI, for example `https://oauth2-proxy.example.com/oauth2/callback`.
8. Save the client and copy the client secret from the **Credentials** tab.

### Audience mapper

OAuth2 Proxy validates the token audience. Configure Keycloak to include the OAuth2 Proxy client ID in the token audience:

1. Go to **Clients** -> `<client-id>` -> **Client scopes**.
2. Open `<client-id>-dedicated`.
3. Click **Configure a new mapper** and choose **Audience**.
4. Set **Name** to `aud-mapper-<client-id>`.
5. Set **Included Client Audience** to `<client-id>`.
6. Enable **Add to ID token**.
7. Enable **Add to access token**.
8. Save the mapper.

If your upstream services require additional audiences, add them deliberately. Keep the `aud` claim limited to intended token recipients.

### Test user

Create or update a test user and ensure:

- the user has an email address matching your `--email-domain` setting,
- the email is marked as verified, unless you intentionally configure OAuth2 Proxy to allow unverified email addresses,
- any required roles or groups are assigned to the user.

## Authorization

OAuth2 Proxy always requires a valid Keycloak login. You can further restrict access with Keycloak groups, realm roles, or client roles.

### Roles

A standard Keycloak installation includes mappers for realm roles and client roles through the predefined `roles` client scope. These roles are included when the client has **Full scope allowed** enabled, which is the Keycloak default.

Create roles as needed:

- Realm role: **Realm roles** -> **Create role**.
- Client role: **Clients** -> `<client-id>` -> **Roles** -> **Create role**.

Assign roles to a user from **Users** -> `<username>` -> **Role mapping** -> **Assign role**.

Authorize realm roles with:

```shell
--allowed-role=<realm-role-name>
```

Authorize client roles with:

```shell
--allowed-role=<client-id>:<client-role-name>
```

To reduce token size, you can limit which realm roles are included for a client: **Clients** -> `<client-id>` -> **Client scopes** -> `<client-id>-dedicated` -> **Scope**. Disable **Full scope allowed**, then assign only the roles that should be emitted in tokens for this client.

### Groups

Authorize group membership with OAuth2 Proxy's standard `--allowed-group` option.

To emit Keycloak groups in tokens:

1. Create a client scope named `groups`.
2. Add a mapper of type **Group Membership**.
3. Set **Token Claim Name** to `groups`, or set it to another claim name and configure OAuth2 Proxy with `--oidc-groups-claim=<claim-name>`.
4. Decide whether to enable **Full group path**.
5. Attach the `groups` client scope to your OAuth2 Proxy client.

If **Full group path** is enabled, include the leading `/` and full path in OAuth2 Proxy:

```shell
--allowed-group=/groupname
--allowed-group=/groupname/child-group
```

If **Full group path** is disabled, use the group name as it appears in the token.

## Verifying token contents

Use the Keycloak console to preview tokens before debugging OAuth2 Proxy:

1. Go to **Clients** -> `<client-id>` -> **Client scopes** -> **Evaluate**.
2. Select a realm user.
3. Generate an ID token or access token.
4. Confirm the token contains the expected `aud`, `groups`, `realm_access`, and `resource_access` claims.

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `invalid audience` or failed audience validation | The OAuth2 Proxy client ID is not in the token `aud` claim | Add an audience mapper for the OAuth2 Proxy client and include it in the ID token. Also include it in the access token if upstreams use that token. |
| `issuer did not match` | `--oidc-issuer-url` does not match Keycloak discovery or token issuer | Use `/realms/<realm>` for Keycloak 17+ and `/auth/realms/<realm>` only for older Keycloak. Fix Keycloak hostname/proxy settings so discovery advertises the public URL. |
| `--allowed-role` does not allow the user | The role is missing from the access token | Ensure the `roles` client scope or equivalent mappers are assigned and the user actually has the realm/client role. |
| `--allowed-group` does not allow the user | Groups claim is missing, uses another claim name, or group path does not match | Add the groups client scope, configure `--oidc-groups-claim` if needed, and match the full path format used in the token. |
| Browser receives very large cookies or NGINX returns header/buffer errors | Tokens contain many groups or roles | Reduce mapped claims or use Redis session storage instead of cookie-only sessions. |

## Legacy admin console notes

Older Keycloak versions used the legacy admin console and the pre-17 `/auth` context path. If you still operate those versions:

1. Create a client with **Access Type** `confidential`, **Client protocol** `openid-connect`, and **Valid Redirect URIs** set to the OAuth2 Proxy callback URL.
2. Copy the secret from the client credentials tab.
3. Create a **Group Membership** mapper with **Token Claim Name** `groups` if you use group authorization.
4. Create an **Audience** mapper with **Included Client Audience** set to your OAuth2 Proxy client ID.
