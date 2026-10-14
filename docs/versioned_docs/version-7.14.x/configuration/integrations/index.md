---
id: index
title: Integrations
---

This section provides configuration examples for integrating OAuth2 Proxy with various reverse proxies, ingress controllers, and Kubernetes web UIs.

## Reverse Proxies and Ingress Controllers

OAuth2 Proxy can be integrated with popular reverse proxies and ingress controllers to add authentication to your applications:

- [Nginx](nginx.md)
- [Traefik](traefik.md)
- [caddy](caddy.md)

## Kubernetes Web UIs

OAuth2 Proxy can also be used to add authentication to Kubernetes web user interfaces:

- [Headlamp](headlamp.md) ✨ *Recommended*
- [Kubernetes Dashboard](kubernetes-dashboard.md) ⚠️ *Deprecated*

:::tip
When integrating with Kubernetes web UIs, make sure to:
1. Configure the Ingress to pass the Authorization header with the bearer token
2. Increase buffer sizes for large OIDC tokens (especially with Azure Entra ID)
3. Set up appropriate Kubernetes RBAC permissions for your users or groups
:::

## General Requirements

Most integrations require the following OAuth2 Proxy configuration:

- `--reverse-proxy=true`: Required to correctly handle `X-Forwarded-*` headers
- **Session storage**: For production deployments with large tokens due to a lot of claims like AD groups, use `--session-store-type=redis`

For provider-specific configuration, see the [OAuth Provider Configuration](../providers/index.md) documentation.

:::note
If you set up your OAuth2 provider to rotate your client secret, you can use the `client-secret-file` option to reload the secret when it is updated.
:::
