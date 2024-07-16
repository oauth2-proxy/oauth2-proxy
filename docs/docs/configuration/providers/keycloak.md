---
id: keycloak
title: Keycloak
---

:::note
This is the legacy provider for Keycloak, use [Keycloak OIDC Auth Provider](keycloak_oidc.md) if possible.
:::

1.  Create new client in your Keycloak realm with **Access Type** 'confidential' and **Valid Redirect URIs** 'https://internal.yourcompany.com/oauth2/callback'
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
