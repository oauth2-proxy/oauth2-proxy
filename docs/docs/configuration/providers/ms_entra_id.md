---
id: ms_entra_id
title: Microsoft Entra ID
---

Provider for Microsoft Entra ID. Fully compliant with OIDC, with support for group overage and multi-tenant apps.

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

## Configure provider
The provider is OIDC-compliant, so all the OIDC parameters are honored. Additional provider-specific configuration parameters are:
* `entra_id_skip_groups_from_graph` - never read groups from Graph API, even when the ID token indicates that there's a group overage. Set if you expect group overage in some cases, but still don't want to grant `User.Read`. Defaults to `false`. If you don't need groups, consider disabling the *groups claim* in the App registration 
* `entra_id_allowed_tenant` - specify an allowed tenant. Use with multi-tenant apps, when incoming tokens are issued by different issuers. When not specified, all tenants are allowed. Redundant for single-tenant apps. Can be specified multiple times.

### Scopes and claims
For single-tenant and multi-tenant apps without groups, the only required scope is `openid` (See: [Scopes and permissions](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc#the-openid-scope)):

To make use of groups - for example use `allowed_groups` setting or authorize based on groups inside your service - you need to enable *groups claims*, so list of your groups is present in the issued ID token (See: [Configure groups](#configure-groups)). No additional scopes are required besides `openid`. This works up to 200 groups.

When user has more than 200 group memberships (See: [group overages](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles#group-overages)), OAuth2-Proxy retrieves the complete list from Microsoft Graph API's [`me/transitiveMemberOf` endpoint](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof). Endpoint requires `User.Read` scope (delegated permission). This permission can be by default consented by user during first login. Set scope to `openid User.Read` to request user consent. OAuth2-Proxy supports up to 999 groups.

Alternatively to user consent, both `openid` and `User.Read` permissions can be consented by admistrator. Then, user is not asked for consent on the first login, and group overage works with `openid` scope only. Admin consent can also be required for some tenants. It can be granted with [azuread_service_principal_delegated_permission_grant](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs/resources/service_principal_delegated_permission_grant) terraform resource.

Reading groups from Graph API can be disabled with `entra_id_skip_groups_from_graph` setting. With this flag set to `true`, even when token will indicate the group overage, there will be no attempt to call Graph API.

For personal microsoft accounts, required scope is `openid profile email`.

See: [Overview of permissions and consent in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview).

### Multi-tenant apps
To use multi-tenant apps, set the appropriate OIDC provider and disable verification:
```shell
oidc_issuer_url=https://login.microsoftonline.com/common/v2.0
insecure_oidc_skip_issuer_verification=true
```
`insecure_oidc_skip_issuer_verification` setting disables following checks:
* Startup check for matching the issuer URL returned from [discovery document](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) with `oidc_issuer_url` setting ([OIDC Discovery 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation)). The document's `issuer` field equals `https://login.microsoftonline.com/{tenantid}/v2.0` which is a template, not the exact value.
* Matching Issuer URL in the ID token with `oidc_issuer_url` setting during ID token validation ([OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) point 2) The tokens are coming from different tenants so the `issuer` is different.

MS Entra ID provider provides additional validation for multi-tenant apps to compensate the disabled verification. By default, every incoming ID token's `issuer` claim is validated to match the `https://login.microsoftonline.com/{tenantid}/v2.0` template. Additionaly, you can limit the allowed tenant IDs by setting `ms_entra_id_allowed_tenants`. 

### Example configurations

Single-tenant app with allowed groups from *groups claim*:
```shell
provider=entra-id
oidc_issuer_url=https://login.microsoftonline.com/<tenant-id>/v2.0
client_id=<client-id>
client_secret=<client-secret>
scope=openid
allowed_groups=["ac51800c-2679-4ecb-8130-636380a3b491"]
```
(For basic authentication in single-tenant app, you can consider using generic OIDC provider)

Single-tenant with group overage and without admin consent:
```shell
provider=entra-id
oidc_issuer_url=https://login.microsoftonline.com/<tenant-id>/v2.0
client_id=<client-id>
client_secret=<client-secret>
scope=openid User.Read
```

Multi-tenant with Microsoft personal accounts & one Entra tenant allowed:
```shell
provider=entra-id
oidc_issuer_url=https://login.microsoftonline.com/common/v2.0
client_id=<client-id>
client_secret=<client-secret>
insecure_oidc_skip_issuer_verification=true
scope=openid profile email
entra_id_allowed_tenants=["9188040d-6c67-4c5b-b112-36a304b66dad","<my-tenant-id>"] # Allow only <my-tenant-id> and Personal MS Accounts tenant 
email_domains="*"
```
