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
| `--entra-id-federated-token-auth` | `entra_id_federated_token_auth` | boolean | Enable oAuth2 client authentication with federated token projected by Entra Workload Identity plugin, instead of client secret.   | false |

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
* Matching ID token's `issuer` claim with `oidc_issuer_url` setting during ID token validation. Required to support tokens issued by different tenants. See [OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

To provide additional security, Entra ID provider performs check on the ID token's `issuer` claim to match the `https://login.microsoftonline.com/{tenant-id}/v2.0` template.

### Workload Identity
Provider supports authentication with federated token, without need of using client secret. Following conditions have to be met:

* Cluster has public OIDC provider URL. For major cloud providers, it can be enabled with a single flag, for example for [Azure Kubernetes Service deployed with Terraform](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster), it's `oidc_issuer_enabled`.
* Workload Identity admission webhook is deployed on the cluster. For AKS, it can be enabled with a flag (`workload_identity_enabled` in Terraform resource), for clusters outside of Azure, it can be installed from [helm chart](https://github.com/Azure/azure-workload-identity).
* Appropriate federated credential is added to application registration.
<details>
    <summary>See federated credential terraform example</summary>
```
    resource "azuread_application_federated_identity_credential" "fedcred" {
        application_id = azuread_application.application.id # ID of your application
        display_name   = "federation-cred"
        description    = "Workload identity for oauth2-proxy"
        audiences      = ["api://AzureADTokenExchange"] # Fixed value
        issuer         = "https://cluster-oidc-issuer-url..."
        subject        = "system:serviceaccount:oauth2-proxy-namespace-name:oauth2-proxy-sa-name" # set proper NS and SA name
    }
```
</details>

* Kubernetes service account associated with oauth2-proxy deployment, is annotated with `azure.workload.identity/client-id: <app-registration-client-id>`
* oauth2-proxy pod is labeled with `azure.workload.identity/use: "true"`
* oauth2-proxy is configured with `entra_id_federated_token_auth` set to `true`.

`client_secret` setting can be omitted when using federated token authentication.

See: [Azure Workload Identity documentation](https://azure.github.io/azure-workload-identity/docs/).

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

Single-tenant app with more than 200 groups and workload identity enabled:
```toml
provider="entra-id"
oidc_issuer_url="https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id="<client-id>"
scope="openid User.Read"
allowed_groups=["968b4844-d5e7-4e18-a834-59927959369f"]
entra_id_federated_token_auth=true
```

Multi-tenant app with Microsoft personal accounts & one Entra tenant allowed, with group overage considered:
```toml
provider="entra-id"
oidc_issuer_url="https://login.microsoftonline.com/common/v2.0"
client_id="<client-id>"
client_secret="<client-secret>"
insecure_oidc_skip_issuer_verification=true
scope="openid profile email User.Read"
entra_id_allowed_tenants=["9188040d-6c67-4c5b-b112-36a304b66dad","<my-tenant-id>"] # Allow only <my-tenant-id> and Personal MS Accounts tenant
email_domains="*"
```

## Kubernetes Dashboard on AKS

This section provides a complete example for integrating oauth2-proxy with Kubernetes Dashboard on Azure Kubernetes Service (AKS) using Entra ID for authentication.

### Architecture

```
User → Nginx Ingress → oauth2-proxy → Entra ID
           ↓
   Kubernetes Dashboard
```

The integration flow:
1. Unauthenticated requests to Dashboard are intercepted by Nginx Ingress
2. Nginx redirects to oauth2-proxy for authentication
3. oauth2-proxy redirects to Entra ID login
4. After successful authentication, oauth2-proxy receives ID token from Entra ID
5. oauth2-proxy sets Authorization header with the bearer token
6. Nginx forwards the request with token to Kubernetes Dashboard
7. Dashboard validates the token and grants access based on AKS RBAC configuration

### Prerequisites

- AKS cluster with Entra ID integration enabled
- Kubernetes Dashboard installed (version 7.x or later)
- NGINX Ingress Controller installed
- Entra ID App Registration configured with:
  - Redirect URI: `https://your-oauth2-domain.com/oauth2/callback`
  - API Permissions: `openid`, `email`, `profile`
  - Groups claim enabled (if using group-based RBAC)
- Users or groups assigned appropriate Kubernetes RBAC permissions

### Alpha Configuration Example

Using [Alpha Configuration](../alpha_config.md) with the oauth2-proxy Helm chart:

```yaml
alphaConfig:
  enabled: true
  configData:
    providers:
      - id: azure-entra
        provider: entra-id
        clientID: YOUR_CLIENT_ID
        clientSecret: YOUR_CLIENT_SECRET
        oidcConfig:
          issuerURL: https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0
          audienceClaims:
            - aud
          emailClaim: email
          groupsClaim: groups
          userIDClaim: oid
        scope: openid email profile

    upstreamConfig:
      upstreams:
        - id: static
          path: /
          static: true
          staticCode: 200

    # Response headers passed to Dashboard via Nginx
    injectResponseHeaders:
      - name: Authorization
        values:
          - claim: id_token
            prefix: "Bearer "
      - name: X-Auth-Request-User
        values:
          - claim: email
      - name: X-Auth-Request-Email
        values:
          - claim: email
      - name: X-Auth-Request-Groups
        values:
          - claim: groups

    server:
      BindAddress: "0.0.0.0:4180"

extraArgs:
  cookie-domain: ".your-domain.com"
  whitelist-domain: ".your-domain.com"
  email-domain: "*"  # Or restrict to your organization
  skip-provider-button: true
  reverse-proxy: true
  pass-authorization-header: true
  set-xauthrequest: true

sessionStorage:
  type: redis

redis:
  enabled: true
  auth:
    enabled: true

ingress:
  enabled: true
  className: nginx
  hosts:
    - oauth2-proxy.your-domain.com
  path: /oauth2
  pathType: Prefix
```

### Kubernetes Dashboard Ingress

**Critical**: The Ingress must include `Authorization` in the `auth-response-headers` annotation:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"

    # OAuth2-proxy authentication
    nginx.ingress.kubernetes.io/auth-url: "https://oauth2-proxy.your-domain.com/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://oauth2-proxy.your-domain.com/oauth2/start?rd=$scheme://$best_http_host$request_uri"

    # Include Authorization header with bearer token
    nginx.ingress.kubernetes.io/auth-response-headers: "Authorization, X-Auth-Request-User, X-Auth-Request-Email"

    # Buffer sizes for large tokens (Entra tokens can exceed 4KB)
    nginx.ingress.kubernetes.io/proxy-buffer-size: "256k"
    nginx.ingress.kubernetes.io/proxy-buffers-number: "4"
    nginx.ingress.kubernetes.io/proxy-busy-buffers-size: "256k"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - dashboard.your-domain.com
      secretName: dashboard-tls
  rules:
    - host: dashboard.your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: kubernetes-dashboard-kong-proxy
                port:
                  number: 443
```

### RBAC Configuration

Assign Kubernetes permissions to Entra ID users or groups.

**User-based:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dashboard-user-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: "user@your-domain.com"  # Email from Entra ID token
    apiGroup: rbac.authorization.k8s.io
```

**Group-based (recommended):**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dashboard-admins-group
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: "YOUR_ENTRA_GROUP_OBJECT_ID"  # Entra ID Group Object ID
    apiGroup: rbac.authorization.k8s.io
```

For production, create custom roles with limited permissions instead of using `cluster-admin`.

### Troubleshooting

**Dashboard still asks for token after authentication**

Verify that:
1. `injectResponseHeaders` in alphaConfig includes Authorization header with id_token claim
2. Dashboard Ingress includes `Authorization` in `auth-response-headers` annotation
3. Buffer sizes are sufficient for large tokens (set to 256k as shown above)
4. Check oauth2-proxy logs for successful token generation: `kubectl logs -n oauth2-proxy <pod-name>`

**"Unauthorized" or "Invalid token" errors**

Common causes:
1. User/group not configured in Kubernetes RBAC
   - Check: `kubectl get clusterrolebindings | grep <user-email>`
2. Token validation failed
   - Verify AKS Entra ID integration is enabled
   - Check Dashboard logs: `kubectl logs -n kubernetes-dashboard <pod-name>`
3. Incorrect oauth2-proxy configuration
   - Ensure `reverse-proxy: true` is set
   - Verify issuer URL matches your tenant

**Groups not included in token**

To include groups in the token:
1. In Entra ID App Registration, go to **Token configuration**
2. Add **groups claim** and select security groups
3. Or edit the manifest and add: `"groupMembershipClaims": "SecurityGroup"`
4. For 200+ groups, ensure scope includes `User.Read` for group overage handling
5. Verify groups appear in token: check oauth2-proxy logs

**Session expires too quickly**

Configure cookie expiration:
```yaml
extraArgs:
  cookie-expire: "24h"
  cookie-refresh: "1h"
```

### Using Workload Identity (Passwordless)

For production environments, use Workload Identity instead of client secrets:

```yaml
config:
  clientID: "YOUR_CLIENT_ID"
  secretKeys:  # Exclude client-secret
    - client-id
    - cookie-secret
  cookieSecret: "YOUR_COOKIE_SECRET"

serviceAccount:
  annotations:
    azure.workload.identity/client-id: YOUR_CLIENT_ID
    azure.workload.identity/tenant-id: YOUR_TENANT_ID

podLabels:
  azure.workload.identity/use: "true"

alphaConfig:
  enabled: true
  configData:
    providers:
      - id: azure-entra
        provider: entra-id
        clientID: YOUR_CLIENT_ID
        oidcConfig:
          issuerURL: https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0
          # ... other config
        entraIdConfig:
          federatedTokenAuth: true
```

This requires:
- AKS with OIDC issuer and Workload Identity enabled
- Federated identity credential configured in Entra ID App Registration
- Service account annotated with `azure.workload.identity/client-id`

See the [Workload Identity section](#workload-identity) above for detailed setup instructions.
