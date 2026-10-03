---
id: bitbucket
title: BitBucket
---

The Bitbucket provider supports both **Bitbucket Cloud** (bitbucket.org, the default) and self-hosted
**Bitbucket Data Center / Server 7.20+** (see [Bitbucket Data Center](#bitbucket-data-center) below).

## Bitbucket Cloud

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

## Bitbucket Data Center

Setting `--bitbucket-datacenter-url` switches the provider to a self-hosted Bitbucket Data Center / Server
(7.20 or later, which added OAuth 2.0 incoming application links). Bitbucket Data Center is not OpenID Connect
compliant, so the `oidc` provider cannot be used with it.

1. As a Bitbucket administrator go to **Administration -> Application Links -> Create link**.
    * Choose **External application**, direction **Incoming**.
    * In "Redirect URL" use `https://<oauth2-proxy>/oauth2/callback`.
    * In "Application permissions" select **Repositories -> Read** if you use `--bitbucket-workspace` or
      `--bitbucket-repository` (requests the `REPO_READ` scope). Otherwise the default `PUBLIC_REPOS` scope is enough.
2. Note the Client ID and Client Secret.

```
   --provider=bitbucket
   --bitbucket-datacenter-url=https://bitbucket.example.com
   --client-id=<Client ID>
   --client-secret=<Client Secret>
```

Include any context path in the URL (for example `https://example.com/bitbucket`). The endpoints are derived from it
and can still be overridden with `--login-url`, `--redeem-url` and `--validate-url`:

| Purpose  | URL                                            |
| -------- | ---------------------------------------------- |
| Login    | `<url>/rest/oauth2/latest/authorize`           |
| Redeem   | `<url>/rest/oauth2/latest/token`               |
| Validate | `<url>/rest/api/latest/application-properties` |

If the instance uses an internal certificate authority, pass it with `--provider-ca-file`.

The restriction options keep their meaning, mapped to Data Center concepts:

| Option                   | Data Center meaning                                                                   |
| ------------------------ | ------------------------------------------------------------------------------------- |
| `--bitbucket-workspace`  | Project key the user must be able to view, e.g. `--bitbucket-workspace=PROJ`          |
| `--bitbucket-repository` | Repository the user must be able to read, as `PROJECTKEY/repo-slug`, e.g. `PROJ/repo` |

When both are set, the user must pass both checks. Note that projects and repositories with public access enabled are
visible to every user.

The session `user` is the Bitbucket user slug, `preferred_username` is the username, and `email` is the user's email
address. Refresh tokens are stored, so `--cookie-refresh` (shorter than the access-token lifetime) keeps sessions
validated against Bitbucket.
