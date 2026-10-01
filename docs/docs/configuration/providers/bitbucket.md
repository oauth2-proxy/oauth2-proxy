---
id: bitbucket
title: BitBucket
---

1. [Add a new OAuth consumer](https://confluence.atlassian.com/bitbucket/oauth-on-bitbucket-cloud-238027431.html)
    * In "Callback URL" use `https://<oauth2-proxy>/oauth2/callback`, substituting `<oauth2-proxy>` with the actual 
      hostname that oauth2-proxy is running on.
    * In Permissions section select:
        * Account -> Email
        * Account -> Read   [Required for workspace membership check]
        * Repositories -> Read
2. Note the Client ID and Client Secret.

To use the provider, pass the following options:

```
   --provider=bitbucket
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```

The default configuration allows everyone with Bitbucket account to authenticate. 

To restrict the access to members of a specific workspace, use the additional configuration option: `--bitbucket-workspace=<Workspace name>`.
 
To restrict the access to users who have write access to one selected repository (contributors) use `--bitbucket-repository=<Repository name>`. Note that repository full name format `owner/repo` is required, for example `--bitbucket-repository=myworkspace/myrepo`.

**Deprecated**: To restrict the access to members of a specific team, use the additional configuration option: `--bitbucket-team=<Team name>`. Note that this option is deprecated and will be removed in a future release. Please use `--bitbucket-workspace` instead. For more info, see [Bitbucket teams API deprecation](https://developer.atlassian.com/cloud/bitbucket/bitbucket-api-teams-deprecation/).

