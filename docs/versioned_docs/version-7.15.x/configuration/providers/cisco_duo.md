---
id: cisco_duo
title: Cisco Duo
---

Cisco Duo SSO can be configured with OAuth2 Proxy using the OIDC provider.

1. Create a new **Generic OIDC Relying Party - Single Sign-On** application in the Duo Admin Portal
2. Configure OAuth2 Proxy with the following options:

```
provider = "oidc"
provider_display_name = "Duo SSO"
scope = "openid email profile"
pass_access_token = true
code_challenge_method = "S256"
```

3. Configure Provider endpoints. Copy the following values from the corresponding fields in the Duo Admin Portal:

```
# Copy from "Client ID" field
client_id = "XXXXXXXX"

# Copy from "Client Secret" field
client_secret = "XXXXXXXX"

# Copy from "Issuer" field
oidc_issuer_url = "https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx"

# Copy from "JWKS URL" field
oidc_jwks_url = "https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/jwks"

# Copy from "Token Introspection URL" field
validate_url = "https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/token_introspection"

# Copy from "UserInfo" field
profile_url = "https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/userinfo"

# Copy from "Token URL" field
redeem_url = "https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/token"
```

4. Complete Configuration by filling in any remaining required fields and save your configuration.
