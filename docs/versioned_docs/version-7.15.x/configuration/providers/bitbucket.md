---
id: bitbucket
title: BitBucket
---

1. [Add a new OAuth consumer](https://confluence.atlassian.com/bitbucket/oauth-on-bitbucket-cloud-238027431.html)
    * In "Callback URL" use `https://<oauth2-proxy>/oauth2/callback`, substituting `<oauth2-proxy>` with the actual 
      hostname that oauth2-proxy is running on.
    * In Permissions section select:
        * Account -> Email
        * Team membership -> Read
        * Repositories -> Read
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=bitbucket
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```

The default configuration allows everyone with Bitbucket account to authenticate. To restrict the access to the team 
members use additional configuration option: `--bitbucket-team=<Team name>`. To restrict the access to only these users 
who have access to one selected repository use `--bitbucket-repository=<Repository name>`.
