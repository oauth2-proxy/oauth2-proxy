---
id: gitlab
title: GitLab
---

## Config Options

| Flag                | Toml Field        | Type           | Description                                                                                                                                                                                                                                                                           | Default |
| ------------------- | ----------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `--gitlab-group`    | `gitlab_groups`   | string \| list | restrict logins to members of any of these groups (slug), separated by a comma                                                                                                                                                                                                        |         |
| `--gitlab-projects` | `gitlab_projects` | string \| list | restrict logins to members of any of these projects (may be given multiple times) formatted as `orgname/repo=accesslevel`. Access level should be a value matching [Gitlab access levels](https://docs.gitlab.com/ee/api/members.html#valid-access-levels), defaulted to 20 if absent |         |

## Usage

This auth provider has been tested against Gitlab version 12.X. Due to Gitlab API changes, it may not work for version 
prior to 12.X (see [994](https://github.com/oauth2-proxy/oauth2-proxy/issues/994)).

Whether you are using GitLab.com or self-hosting GitLab, follow 
[these steps to add an application](https://docs.gitlab.com/ce/integration/oauth_provider.html). Make sure to enable at 
least the `openid`, `profile` and `email` scopes, and set the redirect url to your application url e.g. 
https://myapp.com/oauth2/callback.

If you need projects filtering, add the extra `read_api` scope to your application.

The following config should be set to ensure that the oauth will work properly. To get a cookie secret follow 
[these steps](../overview.md#generating-a-cookie-secret)

```
    --provider="gitlab"
    --redirect-url="https://myapp.com/oauth2/callback" // Should be the same as the redirect url for the application in gitlab
    --client-id=GITLAB_CLIENT_ID
    --client-secret=GITLAB_CLIENT_SECRET
    --cookie-secret=COOKIE_SECRET
```

Restricting by group membership is possible with the following option:

```shell
    --gitlab-group="mygroup,myothergroup"  # restrict logins to members of any of these groups (slug), separated by a comma
```

If you are using self-hosted GitLab, make sure you set the following to the appropriate URL:

```shell
    --oidc-issuer-url="<your gitlab url>"
```

If your self-hosted GitLab is on a subdirectory (e.g. domain.tld/gitlab), as opposed to its own subdomain 
(e.g. gitlab.domain.tld), you may need to add a redirect from domain.tld/oauth pointing at e.g. domain.tld/gitlab/oauth.
