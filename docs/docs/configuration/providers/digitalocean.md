---
id: digitalocean
title: DigitalOcean
---

1. [Create a new OAuth application](https://cloud.digitalocean.com/account/api/applications)
    * You can fill in the name, homepage, and description however you wish.
    * In the "Application callback URL" field, enter: `https://oauth-proxy/oauth2/callback`, substituting `oauth2-proxy` 
      with the actual hostname that oauth2-proxy is running on. The URL must match oauth2-proxy's configured redirect URL.
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=digitalocean
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```

Alternatively, set the equivalent options in the config file. The redirect URL defaults to 
`https://<requested host header>/oauth2/callback`. If you need to change it, you can use the `--redirect-url` command-line option.
