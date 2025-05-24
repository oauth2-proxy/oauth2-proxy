---
id: github
title: GitHub
---

## Config Options

| Flag             | Toml Field     | Type           | Description                                                                                                   | Default |
| ---------------- | -------------- | -------------- | ------------------------------------------------------------------------------------------------------------- | ------- |
| `--github-org`   | `github_org`   | string         | restrict logins to members of this organisation                                                               |         |
| `--github-team`  | `github_team`  | string         | restrict logins to members of any of these teams (slug) or (org:team), comma separated                        |         |
| `--github-repo`  | `github_repo`  | string         | restrict logins to collaborators of this repository formatted as `orgname/repo`                               |         |
| `--github-token` | `github_token` | string         | the token to use when verifying repository collaborators (must have push access to the repository)            |         |
| `--github-user`  | `github_users` | string \| list | To allow users to login by username even if they do not belong to the specified org and team or collaborators |         |

## Usage

1.  Create a new project: https://github.com/settings/developers
2.  Under `Authorization callback URL` enter the correct url ie `https://internal.yourcompany.com/oauth2/callback`

The GitHub auth provider supports two additional ways to restrict authentication to either organization and optional 
team level access, or to collaborators of a repository. Restricting by these options is normally accompanied with `--email-domain=*`. Additionally, all the organizations and teams a user belongs to are set as part of the `X-Forwarded-Groups` header. e.g. `org1:team1,org1:team2,org2:team1`

NOTE: When `--github-user` is set, the specified users are allowed to log in even if they do not belong to the specified 
org and team or collaborators.

To restrict access to your organization:

```shell
    # restrict logins to members of this organisation
    --github-org="your-org"
```

To restrict access to specific teams within an organization:

```shell
    --github-org="your-org"
    # restrict logins to members of any of these teams (slug), comma separated
    --github-team="team1,team2,team3"
```

To restrict to teams within different organizations, keep the organization flag empty and use `--github-team` like so:

```shell
    # keep empty
    --github-org=""
    # restrict logins to members to any of the following teams (format <org>:<slug>, like octo:team1), comma separated
    --github-team="org1:team1,org2:team1,org3:team42,octo:cat"
```

If you would rather restrict access to collaborators of a repository, those users must either have push access to a 
public repository or any access to a private repository:

```shell
    # restrict logins to collaborators of this repository formatted as orgname/repo
    --github-repo=""
```

If you'd like to allow access to users with **read only** access to a **public** repository you will need to provide a 
[token](https://github.com/settings/tokens) for a user that has write access to the repository. The token must be 
created with at least the `public_repo` scope:

```shell
    # the token to use when verifying repository collaborators
    --github-token=""
```

To allow a user to log in with their username even if they do not belong to the specified org and team or collaborators:

```shell
    # allow logins by username, comma separated
    --github-user=""
```

If you are using GitHub enterprise, make sure you set the following to the appropriate url:

```shell
    --login-url="http(s)://<enterprise github host>/login/oauth/authorize"
    --redeem-url="http(s)://<enterprise github host>/login/oauth/access_token"
    --validate-url="http(s)://<enterprise github host>/api/v3"
```
