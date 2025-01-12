---
id: index
title: OAuth Provider Configuration
---

You will need to register an OAuth application with a Provider (Google, GitHub or another provider), and configure it 
with Redirect URI(s) for the domain you intend to run `oauth2-proxy` on.

Valid providers are :

- [ADFS](adfs.md)
- [Bitbucket](bitbucket.md)
- [DigitalOcean](digitalocean.md)
- [Facebook](facebook.md)
- [Gitea](gitea.md)
- [GitHub](github.md)
- [GitLab](gitlab.md)
- [Google](google.md) _default_
- [Keycloak](keycloak.md) (Deprecated)
- [Keycloak OIDC](keycloak_oidc.md)
- [LinkedIn](linkedin.md)
- [login.gov](login_gov.md)
- [Microsoft Azure](ms_azure_ad.md) (Deprecated)
- [Microsoft Entra ID](ms_entra_id.md)
- [Nextcloud](nextcloud.md)
- [OpenID Connect](openid_connect.md)

The provider can be selected using the `provider` configuration value.

Please note that not all providers support all claims. The `preferred_username` claim is currently only supported by the 
OpenID Connect provider.

## Email Authentication

To authorize a specific email-domain use `--email-domain=yourcompany.com`. To authorize individual email addresses use 
`--authenticated-emails-file=/path/to/file` with one email per line. To authorize all email addresses use `--email-domain=*`.

## Adding a new Provider

Follow the examples in the [`providers` package](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/providers/) to define a new
`Provider` instance. Add a new `case` to
[`providers.New()`](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/providers/providers.go) to allow `oauth2-proxy` to use the
new `Provider`.
