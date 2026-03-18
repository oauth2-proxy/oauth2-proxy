---
id: headlamp
title: Headlamp
---

Modern, actively maintained Kubernetes web UI with OAuth2 Proxy integration examples.

**Key features:**
- Active development and maintenance
- Modern, intuitive interface
- Multi-cluster support
- Plugin system
- Works with all OAuth2 providers

## Configuring for use with Headlamp

[Headlamp](https://headlamp.dev/) is a modern, user-friendly Kubernetes web UI that can be integrated with OAuth2 Proxy for authentication. This is a recommended alternative to the deprecated Kubernetes Dashboard.

### Architecture

```
User → Ingress → OAuth2 Proxy → Authentication Provider (e.g., Azure Entra ID)
                      ↓
                  Headlamp
```

### Prerequisites

- Kubernetes cluster (e.g., AKS, EKS, GKE, or self-hosted)
- Headlamp installed in the cluster
- OAuth2 provider configured (Azure Entra ID, Google, GitHub, etc.)
- Ingress controller (Nginx, Traefik, etc.)

### Configuration Overview

When integrating Headlamp with OAuth2 Proxy, the OAuth2 Proxy acts as a reverse proxy in front of Headlamp:

1. User requests access to Headlamp
2. Ingress forwards to OAuth2 Proxy
3. OAuth2 Proxy authenticates the user via the OAuth2 provider
4. After successful authentication, OAuth2 Proxy proxies requests to Headlamp
5. Headlamp receives the authenticated user information via headers

### OAuth2 Proxy Configuration

Configure OAuth2 Proxy to proxy to the Headlamp service:

```yaml
upstreamConfig:
  upstreams:
    - id: headlamp
      path: /
      uri: http://headlamp-service.headlamp-namespace.svc.cluster.local:4466
```

Enable the necessary headers:

```yaml
extraArgs:
  reverse-proxy: true
  pass-authorization-header: true
  set-xauthrequest: true
  email-domain: "*"  # Or restrict to your organization
```

### Example with Azure Entra ID on AKS

For detailed instructions on deploying Headlamp with OAuth2 Proxy on Azure Kubernetes Service using Azure Entra ID, see the official Headlamp documentation:

https://headlamp.dev/docs/latest/installation/in-cluster/aks-cluster-oauth/

Key steps include:

1. **Set up AKS with OIDC**: Enable Microsoft Entra ID authentication with Kubernetes RBAC
2. **Create Azure App Registration**: Configure redirect URI and create client secret
3. **Deploy Headlamp**: Install Headlamp via Helm in your cluster
4. **Deploy OAuth2 Proxy**: Configure OAuth2 Proxy with Entra ID provider settings and upstream pointing to Headlamp
5. **Configure Ingress**: Set up Ingress to route traffic through OAuth2 Proxy to Headlamp
6. **Set RBAC Policies**: Apply Kubernetes RBAC bindings based on users or groups

### Integration with Other Providers

The same integration pattern works with other OAuth2 providers supported by OAuth2 Proxy:

- **Google**: Use the Google provider configuration
- **GitHub**: Use the GitHub provider configuration
- **GitLab**: Use the GitLab provider configuration
- **Keycloak**: Use the Keycloak OIDC provider configuration
- **Any OIDC Provider**: Use the generic OIDC provider configuration

For provider-specific configuration examples, see the [OAuth Provider Configuration](../providers/index.md) documentation.

### Benefits Over Kubernetes Dashboard

Headlamp offers several advantages:

- **Active Development**: Headlamp is actively maintained and developed
- **Modern UI**: Clean, intuitive interface with better UX
- **Plugin System**: Extensible with custom plugins
- **Multi-cluster Support**: Built-in support for managing multiple clusters
- **Desktop App**: Available as both web UI and desktop application

:::note
If you set up your OAuth2 provider to rotate your client secret, you can use the `client-secret-file` option to reload the secret when it is updated.
:::
