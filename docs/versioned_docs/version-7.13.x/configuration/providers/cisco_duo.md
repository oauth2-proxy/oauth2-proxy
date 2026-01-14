---
id: cisco_duo
title: Cisco Duo
---

For Cisco Duo SSO using OIDC, the registration steps are:

1. Setup a "Generic OIDC Relying Party - Single Sign-On" application config in the Duo Admin portal
2. In the Oauth2 Proxy config file, set the following items for OIDC:
    - provider = 'oidc'
    - provider_display_name = 'Duo SSO'
    - scope= "openid email profile"
    - pass_access_token = true
    - code_challenge_method = 'S256'
3. Add the items below into the Oauth2 config file, then copy appropriate information from the Duo Admin Portal as noted:
    - client_id = "XXXXXXXX" ## copy from Client ID field on Duo Admin Portal
    - client_secret = "XXXXXXXX" ## copy from Client Secret field on Duo Admin Portal
    - oidc_issuer_url = 'https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx'  ## copy from Issuer field on Duo Admin Portal
    - oidc_jwks_url = 'https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/jwks' ## copy from JWKS URL field on Duo Admin Portal
    - validate_url = 'https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/token_introspection'  ## copy from Token Introspection URL field on Duo Admin Portal
    - profile_url = 'https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/userinfo'  ## copy from UserInfo field on Duo Admin Portal
    - redeem_url = 'https://sso-xxxxxxxx.sso.duosecurity.com/oidc/xxxxxxxx/token'  ## copy from Token URL field on Duo Admin Portal
4. Fill in the remaining required fields and Save.