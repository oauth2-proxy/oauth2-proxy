---
id: ms_entra_id
title: Microsoft Entra ID
---

Provider for Microsoft Entra ID. Fully compliant with OIDC, with support for group overage and multi-tenant apps.

## Config Options

The provider is OIDC-compliant, so all the OIDC parameters are honored. Additional provider-specific configuration parameters are:

| Flag                        | Toml Field                 | Type           | Description                                                                                                                                                                                                                                                                               | Default |
| --------------------------- | -------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `--entra-id-allowed-tenant` | `entra_id_allowed_tenants` | string \| list | List of allowed tenants. In case of multi-tenant apps, incoming tokens are issued by different issuers and OIDC issuer verification needs to be disabled. When not specified, all tenants are allowed. Redundant for single-tenant apps (regular ID token validation matches the issuer). |         |

## Configure App registration
To begin, create an App registration, set a redirect URI, and generate a secret. All account types are supported, including single-tenant, multi-tenant, multi-tenant with Microsoft accounts, and Microsoft accounts only.

<details>
    <summary>See Azure Portal example</summary>
    <div class="videoBlock">
        <iframe src="https://www.youtube.com/embed/IUNfxhOzr4E"></iframe>
    </div>
</details>

<details>
    <summary>See Terraform example</summary>
```
    resource "azuread_application" "auth" {
        display_name     = "oauth2-proxy"
        sign_in_audience = "AzureADMyOrg" # Others are also supported

        web {
            redirect_uris = [
                "https://podinfo.lakis.tech/oauth2/callback",
            ]
        }
        // We don't specify any required API permissions - we allow user consent only
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

### Configure groups
If you want to make use of groups, you can configure *groups claim* to be present in ID Tokens issued by the App registration.
<details>
    <summary>See Azure Portal example</summary>
    <div class="videoBlock">
        <div class="videoBlock">
            <iframe src="https://www.youtube.com/embed/QZmP5MKEJis"></iframe>
        </div>
    </div>
</details>
<details>
    <summary>See Terraform example</summary>
```
    resource "azuread_application" "auth" {
        display_name     = "oauth2-proxy"
        sign_in_audience = "AzureADMyOrg"

        group_membership_claims = [
            "SecurityGroup"
        ]

        web {
            redirect_uris = [
                "https://podinfo.lakis.tech/oauth2/callback",
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

### Scopes and claims
For single-tenant and multi-tenant apps without groups, the only required scope is `openid` (See: [Scopes and permissions](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc#the-openid-scope)).

To make use of groups - for example use `allowed_groups` setting or authorize based on groups inside your service - you need to enable *groups claims* in the App Registration. When enabled, list of groups is present in the issued ID token. No additional scopes are required besides `openid`. This works up to 200 groups.

When user has more than 200 group memberships, OAuth2-Proxy attempts to retrieve the complete list from Microsoft Graph API's [`transitiveMemberOf`](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof). Endpoint requires `User.Read` scope (delegated permission). This permission can be by default consented by user during first login. Set scope to `openid User.Read` to request user consent. Without proper scope, user with 200+ groups will authenticate with 0 groups. See: [group overages](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles#group-overages).

Alternatively to user consent, both `openid` and `User.Read` permissions can be consented by admistrator. Then, user is not asked for consent on the first login, and group overage works with `openid` scope only. Admin consent can also be required for some tenants. It can be granted with [azuread_service_principal_delegated_permission_grant](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/service_principal_delegated_permission_grant) terraform resource.

For personal microsoft accounts, required scope is `openid profile email`.

See: [Overview of permissions and consent in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview).

### Multi-tenant apps
To authenticate apps from multiple tenants (including personal Microsoft accounts), set the common OIDC issuer url and disable verification:
```toml
oidc_issuer_url=https://login.microsoftonline.com/common/v2.0
insecure_oidc_skip_issuer_verification=true
```
`insecure_oidc_skip_issuer_verification` setting is required to disable following checks:
* Startup check for matching issuer URL returned from [discovery document](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) with `oidc_issuer_url` setting. Required, as document's `issuer` field doesn't equal to `https://login.microsoftonline.com/common/v2.0`. See [OIDC Discovery 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation).
* Matching ID token's `issuer` claim with `oidc_issuer_url` setting during ID token validation. Required to support tokens issued by diffrerent tenants. See [OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). 

To provide additional security, Entra ID provider performs check on the ID token's `issuer` claim to match the `https://login.microsoftonline.com/{tenant-id}/v2.0` template.

### Example configurations
Single-tenant app without groups (*groups claim* not enabled). Consider using generic OIDC provider:
```toml
provider="entra-id"
oidc_issuer_url="https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id="<client-id>"
client_secret="<client-secret>"
scope="openid"
```

Single-tenant app with up to 200 groups (*groups claim* enabled). Consider using generic OIDC provider:
```toml
provider="entra-id"
oidc_issuer_url="https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id="<client-id>"
client_secret="<client-secret>"
scope="openid"
allowed_groups=["ac51800c-2679-4ecb-8130-636380a3b491"]
```

Single-tenant app with more than 200 groups:
```toml
provider="entra-id"
oidc_issuer_url="https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id="<client-id>"
client_secret="<client-secret>"
scope="openid User.Read"
allowed_groups=["968b4844-d5e7-4e18-a834-59927959369f"]
```

Multi-tenant app with Microsoft personal accounts & one Entra tenant allowed, with group overage considered:
```toml
provider="entra-id"
oidc_issuer_url="https://login.microsoftonline.com/common/v2.0"
client_id="<client-id>"
client_secret="<client-secret>"
insecure_oidc_skip_issuer_verification=true
scope="openid profile email User.Read"
entra_id_allowed_tenant=["9188040d-6c67-4c5b-b112-36a304b66dad","<my-tenant-id>"] # Allow only <my-tenant-id> and Personal MS Accounts tenant 
email_domains="*"
```
