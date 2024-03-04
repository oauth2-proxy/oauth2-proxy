---
id: sourcehut
title: SourceHut
---

1.  Create a new OAuth client: https://meta.sr.ht/oauth2
2.  Under `Redirection URI` enter the correct URL, i.e.
    `https://internal.yourcompany.com/oauth2/callback`

To use the provider, start with `--provider=sourcehut`.

If you are hosting your own SourceHut instance, make sure you set the following
to the appropriate URLs:

```shell
    --login-url="https://<meta.your.instance>/oauth2/authorize"
    --redeem-url="https://<meta.your.instance>/oauth2/access-token"
    --profile-url="https://<meta.your.instance>/query"
    --validate-url="https://<meta.your.instance>/profile"
```

The default configuration allows everyone with an account to authenticate.
Restricting access is currently only supported by
[email](#email-authentication).

