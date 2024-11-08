---
id: azure
title: Azure
---

## Config Options

| Flag             | Toml Field     | Type   | Description                                                      | Default    |
| ---------------- | -------------- | ------ | ---------------------------------------------------------------- | ---------- |
| `--azure-tenant` | `azure_tenant` | string | go to a tenant-specific or common (tenant-independent) endpoint. | `"common"` |
| `--resource`     | `resource`     | string | The resource that is protected (Azure AD only)                   |            |

## Usage

1. Add an application: go to [https://portal.azure.com](https://portal.azure.com), choose **Azure Active Directory**, select
   **App registrations** and then click on **New registration**.
2. Pick a name, check the supported account type(single-tenant, multi-tenant, etc). In the **Redirect URI** section create a new
   **Web** platform entry for each app that you want to protect by the oauth2 proxy(e.g.
   https://internal.yourcompanycom/oauth2/callback). Click **Register**.
3. Next we need to add group read permissions for the app registration, on the **API Permissions** page of the app, click on
   **Add a permission**, select **Microsoft Graph**, then select **Application permissions**, then click on **Group** and select
   **Group.Read.All**. Hit **Add permissions** and then on **Grant admin consent** (you might need an admin to do this).
   <br/>**IMPORTANT**: Even if this permission is listed with **"Admin consent required=No"** the consent might actually 
   be required, due to AAD policies you won't be able to see. If you get a **"Need admin approval"** during login, 
   most likely this is what you're missing!
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
  get passed through correctly. Increasing the proxy_buffer_size in nginx or implementing the 
  [redis session storage](../sessions.md#redis-storage) should resolve this.
