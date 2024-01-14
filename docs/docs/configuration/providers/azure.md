---
id: azure
title: Azure
---

## Register an application with the Microsoft identity platform

The Azure provider facilitates authentication through the Microsoft identity platform. Follow the steps outlined below
for basic configuration of the provider. For detailed guidance, refer to the [Microsoft documentation](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app).

1. Add an application.
      1. Navigate to the [Azure Portal](https://portal.azure.com).
      2. Click **Azure Active Directory**
      3. Click **App registrations**.
      4. Click **New registration**.
      5. Enter a name for the application.
      6. Select the supported account type (single-tenant, multi-tenant, etc.).
      7. In the **Redirect URI** section create a new **Web** platform entry for
         each app that you want to protect by the oauth2 proxy (e.g. 
         https://internal.yourcompany.com/oauth2/callback).
      8. Click **Register**.
2. If you want to validate groups using the `--allowed-group` flag, you must add a 
   `groups` claim to the ID token.
   1. Navigate to **Token configuration**.
   2. Select **Add groups claim**.
   3. Select the type of groups you want returned. Selecting "All groups" should work fine for most
      situations, but if you have a large number of groups, you may 
      want to restrict the groups returned to avoid having to grant admin consent to 
      the application (see the next step).

      :::info
   
      Setting "Groups assigned to the application"
      [requires](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal?pivots=portal)
      a Microsoft Entra ID P1 or P2 license.

      :::

   4. If `--azure-graph-group-field` is set to "displayName" **OR** you have 
      users that will have more than 200 groups returned, i.e. a [group overage](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles#group-overages),
      you **must** grant [group member read](https://learn.microsoft.com/en-us/graph/permissions-reference#groupmemberreadall)
      permissions. This requires [administrator consent](https://learn.microsoft.com/en-us/azure/active-directory/develop/permissions-consent-overview?WT.mc_id=Portal-Microsoft_AAD_RegisteredApps#administrator-consent)
      for all tenants that will use the application. Otherwise, the default 
      **User.Read** permission is sufficient for reading the user's group IDs.
      The steps to add the `GroupMember.Read.All` permission are:
      1. Navigate to the **API Permissions** page of the app.
      2. Click **Add a permission**.
      3. Click **Microsoft Graph**.
      4. Click **Delegated permissions**.
      5. Expand the **GroupMember** permissions group.
      6. Select **GroupMember.Read.All**.
      7. Click **Add permissions**.
      8. The permission will be added but administrator consent will be 
         required before it can be used. Click **Grant admin consent for 
         _organization-name_** (you might need an admin to do this).

        :::tip

         For multitenant app registrations, each tenant is required to provide admin consent to the application.
         Instructions on how to request these permissions from a directory admin can be found [here](https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent#request-the-permissions-from-a-directory-admin).
         An example URL for granting admin consent is shown below:

         ```
         https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id={client_id}&scope=https://graph.microsoft.com/.default&redirect_uri=http://localhost:4180/oauth2/callback
         ```
      
         Replace `{client_id}` with your application's client ID. Note that the redirect back to your application does
         not need to be successful for the admin consent to be granted.

        :::

3. On the **Certificates & secrets** page of the app, add a new client secret and note down the value after hitting **Add**.
This will be the value of `client-secret` in the configuration.
4. Select the **Overview** page of the app for help in configuring the proxy.
   1. The **Application (client) ID** is the `client-id`.
   2. Click **Endpoints** to obtain the `oidc-issuer-url` from **OpenID Connect metadata document**.
      Be sure to strip `/.well-known/openid-configuration`
      from the end of the URL. For example, if the URL is
      `https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration`, the `oidc-issuer-url` is
      `https://login.microsoftonline.com/{tenant-id}/v2.0`.

      :::tip
   
       If you've created a multitenant app registration, `tenant-id` will be `organizations`, and you will also need
       to specify the `insecure-oidc-skip-issuer-verify` flag per Microsoft's [documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant#update-your-code-to-handle-multiple-issuer-values).

      :::

   3. The **Client secret** is the `client-secret` you noted down earlier.

:::warning

When using the Azure Auth provider with nginx and the cookie session store you may find the cookie is too large and doesn't 
get passed through correctly. Increasing the `proxy_buffer_size` in nginx or implementing the [redis session storage](sessions.md#redis-storage) 
should resolve this.

:::

## Configuration Examples

### Single Tenant App Registration 

```
   --provider=azure
   --client-id=<Application (client) ID>
   --client-secret=<value from step 3>
   --oidc-issuer-url=https://login.microsoftonline.com/{tenant-id}/v2.0
```

### [Multi-tenant App Registration](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant)

```bash
   --provider=azure
   --client-id=<Application (client) ID>
   --client-secret=<value from step 3>
   --oidc-issuer-url=https://login.microsoftonline.com/organizations/v2.0
   # highlight-next-line
   --insecure-oidc-skip-issuer-verification
```
