---
id: integration
title: Integration
---

This section provides configuration examples for integrating oauth2-proxy with various reverse proxies, ingress controllers, and Kubernetes web UIs.

## Reverse Proxies and Ingress Controllers

oauth2-proxy can be integrated with popular reverse proxies and ingress controllers to add authentication to your applications:

### [Nginx](integrations/nginx.md)

Configure oauth2-proxy with Nginx using the `auth_request` directive. Includes examples for both standalone Nginx configurations and Kubernetes ingress-nginx with annotations.

**Key features:**
- Support for `auth_request` directive
- Kubernetes Ingress annotations
- Multi-part cookie handling for large tokens
- Session refresh support

### [Traefik](integrations/traefik.md)

Set up oauth2-proxy with Traefik v2 using the `ForwardAuth` middleware. Includes examples for both error-based redirects and static upstream configurations.

**Key features:**
- ForwardAuth middleware integration
- Error middleware for 401 redirects
- Static upstream configuration (202 responses)
- Dynamic file configuration examples

### [Caddy](integrations/caddy.md)

Integrate oauth2-proxy with Caddy v2 using the `forward_auth` directive.

**Key features:**
- Simple forward_auth setup
- Automatic header handling
- Custom error handling and redirects

## Kubernetes Web UIs

oauth2-proxy can also be used to add authentication to Kubernetes web user interfaces:

### [Kubernetes Dashboard](integrations/kubernetes-dashboard.md) ⚠️ *Deprecated*

Integration guide for the deprecated Kubernetes Dashboard, including comprehensive Azure Entra ID configuration on AKS.

:::warning Deprecated Project
Kubernetes Dashboard has been deprecated and discontinued as of January 2025. Consider using Headlamp as an alternative.
:::

### [Headlamp](integrations/headlamp.md) ✨ *Recommended*

Modern, actively maintained Kubernetes web UI with oauth2-proxy integration examples.

**Key features:**
- Active development and maintenance
- Modern, intuitive interface
- Multi-cluster support
- Plugin system
- Works with all OAuth2 providers

## General Requirements

Most integrations require the following oauth2-proxy configuration:

- **`--reverse-proxy=true`**: Required to correctly handle `X-Forwarded-*` headers
- **Session storage**: For production deployments with large tokens, use `--session-store-type=redis`

:::tip
When integrating with Kubernetes web UIs, make sure to:
1. Configure the Ingress to pass the Authorization header with the bearer token
2. Increase buffer sizes for large OIDC tokens (especially with Azure Entra ID)
3. Set up appropriate Kubernetes RBAC permissions for your users or groups
:::

For provider-specific configuration, see the [OAuth Provider Configuration](providers/index.md) documentation.

:::note
If you set up your OAuth2 provider to rotate your client secret, you can use the `client-secret-file` option to reload the secret when it is updated.
:::
