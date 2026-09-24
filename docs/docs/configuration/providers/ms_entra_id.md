---
id: ms_entra_id
title: Microsoft Entra ID
---

Provider for Microsoft Entra ID. It uses the Microsoft identity platform OIDC endpoints and adds OAuth2 Proxy support for Entra-specific features such as group overage, multi-tenant allow-listing, and Workload Identity client authentication.

Use this provider for new Microsoft Entra ID deployments. The legacy [`azure`](ms_azure_ad.md) provider is deprecated and should only be used for existing installations that cannot migrate yet.

## Choosing the right configuration

| Scenario | Recommended configuration |
| -------- | ------------------------- |
| Single tenant, no group authorization | `provider="entra-id"` or the generic [`oidc`](openid_connect.md) provider with tenant-specific issuer |
| Single tenant, group authorization with up to 200 groups in the token | `provider="entra-id"`, enable groups claim in the app registration, use `allowed_groups` with Entra group object IDs |
| Users may have more than 200 groups | `provider="entra-id"`, enable groups claim, request Microsoft Graph delegated `User.Read`, and grant consent so OAuth2 Proxy can resolve group overage through Microsoft Graph |
| Multi-tenant application | `provider="entra-id"`, use the `common` issuer, set `insecure_oidc_skip_issuer_verification=true`, and restrict tenants with `entra_id_allowed_tenants` |
| AKS or Kubernetes without client secrets | `provider="entra-id"` with `entra_id_federated_token_auth=true` and Azure Workload Identity |

## Config Options

The provider is OIDC-compliant, so all the OIDC parameters are honored. Additional provider-specific configuration parameters are:

| Flag | Toml Field | Type | Description | Default |
| ---- | ---------- | ---- | ----------- | ------- |
| `--entra-id-allowed-tenant` | `entra_id_allowed_tenants` | string \| list | List of allowed tenant IDs for multi-tenant applications. When not specified, all tenants that pass token validation are allowed. Redundant for single-tenant apps because regular ID token validation already matches the tenant-specific issuer. |         |
| `--entra-id-federated-token-auth` | `entra_id_federated_token_auth` | boolean | Enable OAuth2 client authentication with a federated token projected by Azure Workload Identity instead of a client secret. | false |

## Configure an app registration

Create an app registration in Microsoft Entra ID, set an OAuth2 Proxy callback URL, and choose either a client secret or federated credential for client authentication.

### Microsoft Entra admin center

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com).
2. Go to **Identity** -> **Applications** -> **app registrations** -> **New registration**.
3. Choose the supported account type for your deployment:
   - single tenant for one organization,
   - multi-tenant for multiple organizations,
   - multi-tenant plus personal Microsoft accounts if you need both Entra tenants and personal accounts.
4. Add a **Web** redirect URI for OAuth2 Proxy, for example `https://oauth2-proxy.example.com/oauth2/callback`.
5. After registration, copy the **Application (client) ID** and **Directory (tenant) ID**.
6. For secret-based auth, go to **Certificates & secrets** -> **Client secrets** and create a secret. Copy the secret value immediately.
7. For group authorization, go to **Token configuration** -> **Add groups claim** and include the group types you want in ID tokens.
8. For group overage handling, add Microsoft Graph delegated `User.Read` to the app registration and grant consent according to your tenant policy.
9. For Workload Identity, configure a federated identity credential instead of creating a client secret. See [Workload Identity](#workload-identity).

OIDC scopes such as `openid`, `profile`, and `email` are requested by OAuth2 Proxy in the `scope` setting. Microsoft Graph permissions are API permissions on the app registration and may require user or admin consent.

<details>
    <summary>See Terraform example with client secret</summary>

```hcl
resource "azuread_application" "auth" {
  display_name     = "oauth2-proxy"
  sign_in_audience = "AzureADMyOrg"

  web {
    redirect_uris = [
      "https://oauth2-proxy.example.com/oauth2/callback",
    ]
  }
}

resource "azuread_service_principal" "sp" {
  client_id                    = azuread_application.auth.client_id
  app_role_assignment_required = false
}

resource "azuread_service_principal_password" "pass" {
  service_principal_id = azuread_service_principal.sp.id
}
```
</details>

## Groups and authorization

To authorize with `allowed_groups` or pass groups to an upstream application, enable the groups claim in the app registration. Use Entra group **object IDs** in `allowed_groups`; display names are not stable identifiers and are not what Entra emits in the `groups` claim.

```toml
allowed_groups = ["ac51800c-2679-4ecb-8130-636380a3b491"]
```

<details>
    <summary>See Terraform example with groups claim</summary>

```hcl
resource "azuread_application" "auth" {
  display_name     = "oauth2-proxy"
  sign_in_audience = "AzureADMyOrg"

  group_membership_claims = [
    "SecurityGroup"
  ]

  web {
    redirect_uris = [
      "https://oauth2-proxy.example.com/oauth2/callback",
    ]
  }
}
```
</details>

### Group overage

Microsoft Entra ID includes up to 200 groups in a JWT. If the user is a member of more groups, Entra emits an overage indicator instead of the full group list. OAuth2 Proxy detects that indicator and calls Microsoft Graph `/me/transitiveMemberOf` to add the user's groups to the session.

For group overage to work:

- add Microsoft Graph delegated `User.Read` to the app registration,
- include `User.Read` in OAuth2 Proxy's `scope` when it needs to be requested during sign-in,
- ensure the user or an administrator can consent to that permission.

Without the required permission and consent, users with group overage may authenticate successfully but have no groups in the OAuth2 Proxy session, causing `allowed_groups` checks to fail.

Personal Microsoft accounts do not support the same Entra group model. Use group authorization and group overage handling for work or school accounts in Entra tenants.

See:

- [Microsoft identity platform group overage claims](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles#group-overages)
- [Microsoft Graph transitiveMemberOf](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof)
- [Overview of permissions and consent](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)

## Scopes and claims

For single-tenant and multi-tenant apps without groups, the only required OIDC scope is `openid` (see [Scopes and permissions](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc#the-openid-scope)).

Common scope choices:

| Scenario | Scope |
| -------- | ----- |
| Work or school account, no groups | `openid` |
| Work or school account with group overage support | `openid User.Read` |
| Personal Microsoft accounts | `openid profile email` |
| Multi-tenant including personal accounts and group overage for Entra tenants | `openid profile email User.Read` |

Use `oidc_email_claim`, `oidc_groups_claim`, and `oidc_audience_claims` only when you need to override OAuth2 Proxy defaults. For Kubernetes RBAC and other systems that need stable user identifiers, consider using the Entra `oid` claim via `userIDClaim` in AlphaConfig.

## Multi-tenant apps

To authenticate users from multiple tenants, including personal Microsoft accounts, use the common issuer and disable strict issuer verification:

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/common/v2.0"
insecure_oidc_skip_issuer_verification = true
```

`insecure_oidc_skip_issuer_verification` is required because tokens are issued by tenant-specific issuers such as `https://login.microsoftonline.com/<tenant-id>/v2.0`, while the configured discovery URL is `common`.

:::warning
When issuer verification is disabled for a multi-tenant app, set `entra_id_allowed_tenants` unless you intentionally allow users from any tenant. Treat the allowed tenant list as the trust boundary for multi-tenant deployments.
:::

OAuth2 Proxy still validates that the token issuer follows the expected Microsoft Entra issuer format. `entra_id_allowed_tenants` then restricts which tenant IDs are accepted. Use tenant IDs rather than tenant domains. The tenant ID for personal Microsoft accounts is `9188040d-6c67-4c5b-b112-36a304b66dad`.

```toml
entra_id_allowed_tenants = [
  "9188040d-6c67-4c5b-b112-36a304b66dad",
  "<your-tenant-id>"
]
```

## Workload Identity

OAuth2 Proxy can authenticate to Entra ID with a federated token instead of a client secret. This is commonly used with [Azure Workload Identity](https://azure.github.io/azure-workload-identity/docs/) on AKS or other Kubernetes clusters.

Checklist:

- The cluster has a public OIDC issuer URL.
- The Azure Workload Identity admission webhook is installed or enabled.
- The app registration has a federated identity credential whose subject exactly matches the OAuth2 Proxy service account: `system:serviceaccount:<namespace>:<service-account>`.
- The OAuth2 Proxy Kubernetes service account is annotated with `azure.workload.identity/client-id: <app-registration-client-id>`.
- On AKS, also set `azure.workload.identity/tenant-id: <tenant-id>` when your setup requires it.
- The OAuth2 Proxy pod is labeled with `azure.workload.identity/use: "true"`.
- OAuth2 Proxy is configured with `entra_id_federated_token_auth=true`.
- `client_secret` is omitted.
- The admission webhook injects `AZURE_FEDERATED_TOKEN_FILE`; OAuth2 Proxy validates this variable at startup when federated token auth is enabled.

<details>
    <summary>See federated credential Terraform example</summary>

```hcl
resource "azuread_application_federated_identity_credential" "fedcred" {
  application_id = azuread_application.auth.id
  display_name   = "oauth2-proxy"
  description    = "Workload identity for oauth2-proxy"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://cluster-oidc-issuer-url.example.com"
  subject        = "system:serviceaccount:oauth2-proxy:oauth2-proxy"
}
```
</details>

## Example configurations

### Single tenant without groups

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<client-id>"
client_secret = "<client-secret>"
scope = "openid"
```

### Single tenant with groups in the token

Enable groups claim in the app registration first.

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<client-id>"
client_secret = "<client-secret>"
scope = "openid"
allowed_groups = ["ac51800c-2679-4ecb-8130-636380a3b491"]
```

### Single tenant with group overage support

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<client-id>"
client_secret = "<client-secret>"
scope = "openid User.Read"
allowed_groups = ["968b4844-d5e7-4e18-a834-59927959369f"]
```

### Single tenant with group overage and Workload Identity

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<client-id>"
scope = "openid User.Read"
allowed_groups = ["968b4844-d5e7-4e18-a834-59927959369f"]
entra_id_federated_token_auth = true
```

### Multi-tenant with one Entra tenant and personal Microsoft accounts allowed

```toml
provider = "entra-id"
oidc_issuer_url = "https://login.microsoftonline.com/common/v2.0"
client_id = "<client-id>"
client_secret = "<client-secret>"
insecure_oidc_skip_issuer_verification = true
scope = "openid profile email User.Read"
entra_id_allowed_tenants = [
  "9188040d-6c67-4c5b-b112-36a304b66dad",
  "<your-tenant-id>"
]
email_domains = ["*"]
```

### AlphaConfig provider example

```yaml
providers:
  - id: entra
    provider: entra-id
    clientID: <client-id>
    clientSecret: <client-secret>
    oidcConfig:
      issuerURL: https://login.microsoftonline.com/<tenant-id>/v2.0
      emailClaim: email
      groupsClaim: groups
      userIDClaim: oid
    scope: openid
    allowedGroups:
      - ac51800c-2679-4ecb-8130-636380a3b491
```

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| Users from unexpected tenants can sign in | Multi-tenant issuer is configured without `entra_id_allowed_tenants` | Add an allowed tenant list or use a tenant-specific issuer for single-tenant apps. |
| Users with many groups fail `allowed_groups` | Group overage occurred but Graph permission or consent is missing | Add Microsoft Graph delegated `User.Read`, include it in `scope` if it must be requested during sign-in, and grant consent as required. |
| `allowed_groups` never matches | Display names were used instead of object IDs, or groups claim is not enabled | Enable groups claim and configure `allowed_groups` with Entra group object IDs. |
| Cookie or header size errors | ID token contains many groups or claims | Use Redis session storage and limit emitted claims where possible. |
| Workload Identity startup validation fails | `AZURE_FEDERATED_TOKEN_FILE` was not injected or is unreadable | Verify service account annotations, pod label, webhook installation, and federated credential subject. |

## Kubernetes integrations

For Kubernetes web UI examples with Microsoft Entra ID, see:

- [Headlamp](../integrations/headlamp.md), the recommended actively maintained Kubernetes UI.
- [Kubernetes Dashboard](../integrations/kubernetes-dashboard.md), retained for users of the deprecated Kubernetes Dashboard project.
