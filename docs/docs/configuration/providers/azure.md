---
id: azure
title: Azure
---

1. Add an application.
   1. Navigate to the [Azure Portal](https://portal.azure.com).
   2. Click **Azure Active Directory**
   3. Click **App registrations**.
   4. Click **New registration**.
   5. Enter a name for the application.
   6. Select the supported account type (single-tenant, multi-tenant, etc.).
   7. In the **Redirect URI** section create a new **Web** platform entry for each app that you want to protect by the oauth2 proxy (e.g. 
   https://internal.yourcompanycom/oauth2/callback).
   8. Click **Register**.
2. If you want to validate groups using the `--allowed-group` flag, add a 
   `groups` claim to the ID token.
   1. Go to **Token configuration** and **Add groups claim**. Select "All 
      groups" or "SecurityGroup" based on which groups for a user you want 
      returned in the claim. If you have a large number of groups, you may 
      want to select "Groups assigned to the application" to limit the 
      number of groups returned to avoid having to grant admin consent to 
      the application.
   2. If `--azure-graph-group-field` is set to "displayName" **OR** you have 
      users that will have more than 200 groups returned, you **must** 
      grant group member read permissions.
      This requires [administrator consent](https://learn.microsoft.com/en-us/azure/active-directory/develop/permissions-consent-overview?WT.mc_id=Portal-Microsoft_AAD_RegisteredApps#administrator-consent)
      for all tenants that will use the application. If not set, the default 
      **User.Read** permission is sufficient for reading the user's group IDs.
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
3. On the **Certificates & secrets** page of the app, add a new client secret and note down the value after hitting **Add**.
This will be the value of `client-secret` in the configuration.
4. Select the **Overview** page of the app for help in configuring the proxy.
   1. The **Application (client) ID** is the `client-id`.
   2. The **Directory (tenant) ID** is the `azure-tenant`. This flag is not necessary for multi-tenant applications.
   3. Click **Endpoints** to obtain the `oidc-issuer-url` from **OpenID Connect metadata document**. Be sure to strip `/.well-known/openid-configuration`
from the end of the URL. For example, if the URL is `https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration`, the `oidc-issuer-url` is `https://login.microsoftonline.com/{tenant-id}/v2.0`.
If `tenant-id` is `common` or `organizations`, you also need to specify the `insecure-oidc-skip-issuer-verify` flag per Microsoft's [documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant#update-your-code-to-handle-multiple-issuer-values).
   4. The **Client secret** is the `client-secret` you noted down earlier.

***Notes***:
- When using the Azure Auth provider with nginx and the cookie session store you may find the cookie is too large and doesn't 
get passed through correctly. Increasing the proxy_buffer_size in nginx or implementing the [redis session storage](sessions.md#redis-storage) 
should resolve this.

#### Configuration Examples

##### v2 Azure Auth endpoint (Microsoft Identity Platform Endpoints - https://login.microsoftonline.com/common/oauth2/v2.0/authorize)
```
   --provider=azure
   --client-id=<Application (client) ID>
   --client-secret=<value from step 3>
   --azure-tenant={tenant-id}
   --oidc-issuer-url=https://login.microsoftonline.com/{tenant-id}/v2.0
```

##### [Multi-tenant Configuration](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant)

```
   --provider=azure
   --client-id=<Application (client) ID>
   --client-secret=<value from step 4>
   --oidc-issuer-url=https://login.microsoftonline.com/organizations/v2.0
   --insecure-oidc-skip-issuer-verification
```
