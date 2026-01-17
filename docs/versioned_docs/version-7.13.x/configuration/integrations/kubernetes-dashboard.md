---
id: kubernetes-dashboard
title: Kubernetes Dashboard
---

:::warning Deprecated Project
Kubernetes Dashboard has been deprecated and discontinued as of January 2025. See the [official announcement](https://github.com/kubernetes/dashboard/commit/0ba796dce6916bb6ca5da5ca0b3ab22cecfd1e18) for more information.

You may want to consider alternative solutions such as [Headlamp](./headlamp.md).
:::

## Kubernetes Dashboard on AKS with Azure Entra ID

Integration guide for the deprecated Kubernetes Dashboard, including comprehensive Azure Entra ID configuration on AKS with detailed troubleshooting and RBAC setup.

### Architecture

```
User → Nginx Ingress → OAuth2 Proxy → Entra ID
           ↓
   Kubernetes Dashboard
```

The integration flow:
1. Unauthenticated requests to Dashboard are intercepted by Nginx Ingress
2. Nginx redirects to OAuth2 Proxy for authentication
3. OAuth2 Proxy redirects to Entra ID login
4. After successful authentication, OAuth2 Proxy receives ID token from Entra ID
5. OAuth2 Proxy sets Authorization header with the bearer token
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

Using [Alpha Configuration](../alpha_config.md) with the OAuth2 Proxy Helm chart:

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
    - OAuth2 Proxy.your-domain.com
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

    # OAuth2 Proxy authentication
    nginx.ingress.kubernetes.io/auth-url: "https://OAuth2 Proxy.your-domain.com/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://OAuth2 Proxy.your-domain.com/oauth2/start?rd=$scheme://$best_http_host$request_uri"

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
4. Check OAuth2 Proxy logs for successful token generation: `kubectl logs -n OAuth2 Proxy <pod-name>`

**"Unauthorized" or "Invalid token" errors**

Common causes:
1. User/group not configured in Kubernetes RBAC
   - Check: `kubectl get clusterrolebindings | grep <user-email>`
2. Token validation failed
   - Verify AKS Entra ID integration is enabled
   - Check Dashboard logs: `kubectl logs -n kubernetes-dashboard <pod-name>`
3. Incorrect OAuth2 Proxy configuration
   - Ensure `reverse-proxy: true` is set
   - Verify issuer URL matches your tenant

**Groups not included in token**

To include groups in the token:
1. In Entra ID App Registration, go to **Token configuration**
2. Add **groups claim** and select security groups
3. Or edit the manifest and add: `"groupMembershipClaims": "SecurityGroup"`
4. For 200+ groups, ensure scope includes `User.Read` for group overage handling
5. Verify groups appear in token: check OAuth2 Proxy logs

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

For detailed Workload Identity setup instructions, see the [Workload Identity section](../providers/ms_entra_id.md#workload-identity) in the Microsoft Entra ID provider documentation.

## Integration with Other Providers

While this guide focuses on Azure Entra ID, Kubernetes Dashboard can be integrated with other OAuth2 providers supported by OAuth2 Proxy. The key requirements remain the same:

1. **Authorization Header**: Pass the bearer token via the `Authorization` header
2. **RBAC Configuration**: Configure Kubernetes RBAC for your authentication provider's users/groups
3. **Buffer Sizes**: Ensure adequate buffer sizes for tokens (especially important for OIDC providers)

For provider-specific configuration examples, see the [OAuth Provider Configuration](../providers/index.md) documentation.
