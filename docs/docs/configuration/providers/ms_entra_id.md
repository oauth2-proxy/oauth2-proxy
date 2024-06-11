---
id: ms_entra_id
title: Microsoft Entra ID
---
OIDC-compliant provider for Microsoft Entra ID (Azure AD successor) application registrations. This providers support the Azure OAuth V2 endpoint only, if you want to use the V1 endpoint, try the legacy [azure](azure.md) provider.

## Configure application registration
To start, create an App registration with minimal permissions, assign a redirect URI, and generate a secret. All account types are supported (Single tenant, multi-tenant, multi-tenant with MS accounts, and MS accounts only).
<details>
    <summary>See Azure Portal example</summary>
    <div class="videoBlock">
        <iframe src="https://www.youtube.com/embed/IUNfxhOzr4E"></iframe>
    </div>

When created with Portal, App registration automatically creates a delegated API permission for `User.Read`. 
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

        required_resource_access {
            resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
            resource_access {
                id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read delegated
                type = "Scope"
            }
        }
    }

    resource "azuread_application_password" "apppass" {
        application_id = azuread_application.auth.id
    }

    # For single-tenant app, consider using service principal password instead of app password
    resource "azuread_service_principal" "sp" {
        client_id                    = azuread_application.auth.client_id
        app_role_assignment_required = false
    }

    resource "azuread_service_principal_password" "pass" {
        service_principal_id = azuread_service_principal.sp.id
    }

```
</details>

This configuration is sufficient for a simple authentication scenario with single-tenant app registration.

### Configure `groups` claim
If you want to make use of groups (i.e., use `--allowed-group` or authorize based on groups inside your service), you need to configure `groups` claim to be present in the ID token:
<details>
    <summary>See Azure Portal example</summary>
    <div class="videoBlock">
        <div class="videoBlock">
            <iframe src="https://www.youtube.com/embed/IUNfxhOzr4E"></iframe>
        </div>
    </div>
</details>
<details>
    <summary>See Terraform example</summary>
```
    resource "azuread_application" "auth" {
        display_name     = "oauth2-proxy"
        sign_in_audience = "AzureADMyOrg" # Other alre also supported

        group_membership_claims = [
            "SecurityGroup"
        ]
        optional_claims {
            id_token {
                name = "groups"
            }
        }

        web {
            redirect_uris = [
                "https://podinfo.lakis.tech/oauth2/callback",
            ]
        }

        required_resource_access {
            resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
            resource_access {
                id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read delegated
                type = "Scope"
            }
        }
    }

    resource "azuread_application_password" "apppass" {
        application_id = azuread_application.auth.id
    }

```
</details>


### Configure group overage support
Azure has a limit of 200 groups in the JWT. If you can't avoid such a big number and still want to access the groups, you need to grant `GroupMember.Read.All` delegated permission to the app registration so oauth2-proxy can read all the groups from Graph API. **NOTE**: This permission by default requires an admin consent!
<details>
    <summary>See Azure Portal example</summary>
    <div class="videoBlock">
        <div class="videoBlock">
            <iframe src="https://www.youtube.com/embed/6pNsU7TY1AU"></iframe>
        </div>
    </div>
</details>
<details>
    <summary>See Terraform example</summary>
```
    resource "azuread_application" "auth" {
        display_name     = "oauth2-proxy"
        sign_in_audience = "AzureADMyOrg" # Other alre also supported

        group_membership_claims = [
            "SecurityGroup"
        ]
        optional_claims {
            id_token {
                name = "groups"
            }
        }

        web {
            redirect_uris = [
                "https://podinfo.lakis.tech/oauth2/callback",
            ]
        }

        required_resource_access {
            resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
            resource_access {
                id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read delegated
                type = "Scope"
            }
            
            resource_access {
                id   = "bc024368-1153-4739-b217-4326f2e966d0" # GroupMember.Read.All delegated - admin consent required
                type = "Scope"
            }

        }
    }

    resource "azuread_application_password" "apppass" {
        application_id = azuread_application.auth.id
    }
```
Admin consent is required after creation by Terraform
</details>

## Configure provider
The provider is OIDC-compliant, so all the OIDC parameters are honored. Additional provider-specific configuration parameters are:
* `entra-id-skip-groups-from-graph` - never read groups from Graph API, even when the ID token indicates that there's a group overage. Set if you expect group overage in some cases, but still don't want to assign wide `GroupMember.Read.All`. Defaults to `false`. If you don't need groups, consider skipping the `groups` claim in the app registration.
* `entra-id-allowed-tenant` - specify an allowed tenant. Use with multi-tenant apps, when incoming tokens are issued by different issuers. When not specified, all tenants are allowed. Redundant for single-tenant apps.

### Scope
For Azure-only apps (multi-tenant and single-tenant), the only required OAuth scope is `openid`:
```shell
- --scope=openid
```
For personal MS accounts, the scope has to be extended with `email` and `profile`:
```shell
- --scope=openid profile email
```
It's recommended to configure the scopes explicitly, otherwise, you may experience issues with allowing groups (Azure doesn't support the `groups` scope which is automatically included when you configure allowed groups).

### Single-tenant
Simple single-tenant configuration:
```shell
- --provider=entra-id
- --oidc-issuer-url=https://login.microsoftonline.com/{tenantId}/v2.0
- --client-id=<valid-client-id>
- --client-secret=<valid-client-secret>
- --scope=openid
```

### Multi-tenant
Multi-tenant apps require you to disable OIDC issuer verification, as `issuer` field in the [discovery document](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration) is a template, not an exact value:
```shell
- --provider=entra-id
- --oidc-issuer-url=https://login.microsoftonline.com/common/v2.0
- --client-id=<valid-client-id>
- --client-secret=<valid-client-secret>
- --insecure-oidc-skip-issuer-verification
- --scope=openid profile email
```

The configuration above insecurely allows all tenants. To allow specific tenants, use the configuration below as an example:
```shell
- --provider=entra-id
- --oidc-issuer-url=https://login.microsoftonline.com/common/v2.0
- --client-id=<valid-client-id>
- --client-secret=<valid-client-secret>
- --entra-id-allowed-tenant=66209a4a-80f3-4602-8126-2193115722f8
- --entra-id-allowed-tenant=a47d1522-8e8c-4546-a2c8-d6590ea9d6f3
- --insecure-oidc-skip-issuer-verification
- --scope=openid profile email
```
