---
id: index
title: OAuth Provider Configuration
---

You will need to register an OAuth application with a Provider (Google, GitHub or another provider), and configure it 
with Redirect URI(s) for the domain you intend to run `oauth2-proxy` on.

Valid providers are :

- [Google](google.md) _default_
- [Azure](azure.md)
- [ADFS](adfs.md)
- [Facebook](facebook.md)
- [GitHub](github.md)
- [Gitea](gitea.md)
- [Keycloak](keycloak.md)/[Keycloak OIDC](keycloak_oidc.md)
- [GitLab](gitlab.md)
- [LinkedIn](linkedin.md)
- [Microsoft Azure AD](azure_ad.md)
- [OpenID Connect](openid_connect.md)
- [login.gov](login_gov.md)
- [Nextcloud](nextcloud.md)
- [DigitalOcean](digitalocean.md)
- [Bitbucket](bitbucket.md)

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
