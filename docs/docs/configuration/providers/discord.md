---
id: discord
title: Discord
---

## Config Options

| Flag                 | Toml Field          | Type           | Description                                              | Default |
| -------------------- | ------------------- | -------------- | -------------------------------------------------------- | ------- |
| `--discord-restricted-user-id` | `discord_restricted_user_ids` | string \| list | restricts logins to a specific list of discord users. Not specifying a list of users means every one is allowed to access. |         |

## Usage

***Application Setup***
1.  Create a new Discord App from https://discord.com/developers/applications/
    * The Application Name will be what appears when users attempt to authenticate.
2.  On the left hand side of the application information page, navigate to "OAuth2".
3.  On this page, keep track of the Client ID and reset the Client Secret to generate a new secret.
4.  Under Redirects, add your Valid OAuth redirect URIs to `https://<proxied host>oauth2/callback`

***Finding discord user identifiers***

To find a user's Discord ID (including your own), right-click their profile picture and select Copy ID.

***Using the provider***

To use the provider, pass the following options:

```
   --provider=discord
   --client-id=<Client ID from Step 3>
   --client-secret=<Client Secret from Step 3>
   --discord-restricted-user-id=<user_id> 
```

The `--discord-restricted-user-id` arg can be specified multiple times with different guild IDs to allow multiple guilds 
to authenticate.