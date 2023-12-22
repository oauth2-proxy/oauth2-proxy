---
id: azure
title: Azure
---

You need to create an App Registration in Azure Entra ID and configure oauth2-proxy with certificate credential or client secret.

### Create App Registration
##### Create App Registration in Portal
1. Add an application: go to [https://portal.azure.com](https://portal.azure.com), choose **Azure Active Directory**, select
   **App registrations** and then click on **New registration**.
2. Pick a name, check the supported account type(single-tenant, multi-tenant, etc). In the **Redirect URI** section create a new **Web** platform entry for each app that you want to protect by the oauth2 proxy(e.g. https://internal.yourcompany.com/oauth2/callback). Click **Register**.
3. Add permission to App Registration - on the **API Permissions** page of the app, click on **Add a permission**, select **Microsoft Graph**, then select **Delegated permissions**. Expand "User" section and select **User.Read**, then **Add permissions**. If you use V1 authentication, or have unusual tenant configuration, you may also need an Application permission - **Group.Read.All** and an admin consent.

##### Create App registration with Terraform
Minimal example of App Registration with redirect URI & `User.Read` Graph permission:
```
provider azuread {}

resource "azuread_application" "auth" {
  display_name = "oauth2-proxy"

  web {
    redirect_uris = [
      "https://internal.yourcompany.com/oauth2/callback",
    ]
  }

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
      type = "Scope"
    }
  }
}
```
See [terraform documentation for azuread_application](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/application)

### Configure oauth2-proxy
You can configure oauth2-proxy with App registration in two ways - workload identity or client secret. Workload identity is recommended as it doesn't require to store any secrets on the cluster.

##### Workload identity configuration
Make sure you have:
1. Kubernetes cluster with OIDC exposed exposed publicly. For Azure Kubernetes Service, the OIDC endpoint can be [easily enabled](https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer), same with other managed Kubernetes services. For on-premises - see [Installation section](https://azure.github.io/azure-workload-identity/docs/installation.html) about how to expose OIDC endpoint and manage keys.
2. Install Azure Workload Identity webhook on the cluster. For AKS, you can enable it by [an appropriate flag](https://learn.microsoft.com/en-us/azure/aks/learn/tutorial-kubernetes-workload-identity). For on premises and other cloud providers, [azure workload identity webhook server](https://github.com/Azure/azure-workload-identity) can be installed with helm.
3. Create federated credential for you application by following [official documentation](https://azure.github.io/azure-workload-identity/docs/topics/federated-identity-credential.html#federated-identity-credential-for-an-azure-ad-application-1). Alternatively, you can use terraform [azuread_application_federated_identity_credential](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/application_federated_identity_credential) resource:
```
resource "azuread_application_federated_identity_credential" "oauth2-proxy" {
  application_id = azuread_application.auth.id
  display_name   = "oauth2-proxy"
  description    = "oauth2-proxy"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://storage.googleapis.com/lakisoidcc3"
  subject        = "system:serviceaccount:oauth2-proxy:oauth2-proxy"
}
```
4. Annotate and label `oauth2-proxy` service account with workload identity-specific settings:
```
annotations:
  azure.workload.identity/client-id: d9f1d870-d52c-4cf2-a399-f3594c843a36
```
* Label `oauth2-proxy` pod with workload identity-specific settings:
```
labels:
  azure.workload.identity/use: "true"
```
And start `oauth2-proxy` with federated credentials enabled:
```
    --provider=azure
    --oidc-issuer-url=https://login.microsoftonline.com/{tenant-id}/v2.0
    --client-id={client-id}
    --azure-federated-token-auth-enabled
```

##### Client secret configuration using Portal
1. On the **Certificates & secrets** page of the app, add a new client secret and note down the value after hitting **Add**.
2. Configure the proxy with:
```
   --provider=azure
   --client-id={application-id}
   --client-secret={client-secret}
   --azure-tenant={tenant-id}
   --oidc-issuer-url=https://login.microsoftonline.com/{tenant-id}/v2.0
```
NOTE: for V1 Azure Auth endpoint, the OIDC URL is `https://sts.windows.net/{tenant-id}/`

***Notes***:
- When using v2.0 Azure Auth endpoint (`https://login.microsoftonline.com/{tenant-id}/v2.0`) as `--oidc_issuer_url`, in conjunction
  with `--resource` flag, be sure to append `/.default` at the end of the resource name. See
  https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#the-default-scope for more details.
- When using the Azure Auth provider with nginx and the cookie session store you may find the cookie is too large and doesn't
  get passed through correctly. Increasing the proxy_buffer_size in nginx or implementing the 
  [redis session storage](../sessions.md#redis-storage) should resolve this.