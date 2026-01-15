---
id: kubernetes-dashboard
title: Kubernetes Dashboard
---

:::warning Deprecated Project
Kubernetes Dashboard has been deprecated and discontinued as of January 2025. See the [official announcement](https://github.com/kubernetes/dashboard/commit/0ba796dce6916bb6ca5da5ca0b3ab22cecfd1e18) for more information.

You may want to consider alternative solutions such as [Headlamp](./headlamp.md).
:::

## Kubernetes Dashboard on AKS with Azure Entra ID

For a complete example of integrating oauth2-proxy with Kubernetes Dashboard on Azure Kubernetes Service (AKS) using Azure Entra ID for authentication, including RBAC configuration and troubleshooting, see the [Kubernetes Dashboard on AKS](../providers/ms_entra_id.md#kubernetes-dashboard-on-aks) section in the Microsoft Entra ID provider documentation.

### Key Integration Points

When integrating Kubernetes Dashboard with oauth2-proxy, keep in mind:

1. **Authorization Header**: The Ingress must include `Authorization` in the `auth-response-headers` annotation to pass the bearer token to the Dashboard
2. **Buffer Sizes**: Entra ID tokens can exceed 4KB, so you need to increase nginx buffer sizes (e.g., `proxy-buffer-size: 256k`)
3. **RBAC Configuration**: Users or groups must be assigned appropriate Kubernetes RBAC permissions
4. **Token Claims**: Configure oauth2-proxy to inject the ID token in the Authorization header with the Bearer prefix

### Integration Flow

```
User → Nginx Ingress → oauth2-proxy → Authentication Provider (e.g., Entra ID)
           ↓
   Kubernetes Dashboard
```

1. Unauthenticated requests to Dashboard are intercepted by Nginx Ingress
2. Nginx redirects to oauth2-proxy for authentication
3. oauth2-proxy redirects to the authentication provider
4. After successful authentication, oauth2-proxy receives ID token
5. oauth2-proxy sets Authorization header with the bearer token
6. Nginx forwards the request with token to Kubernetes Dashboard
7. Dashboard validates the token and grants access based on RBAC configuration

For detailed configuration examples, refer to the provider-specific documentation:
- [Microsoft Entra ID (Azure AD) integration](../providers/ms_entra_id.md#kubernetes-dashboard-on-aks)
