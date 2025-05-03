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

To find a user's Discord ID (including your own), first activate the developer mode,
then right-click their profile picture and select Copy ID.

***Scopes***

Scopes are defined on [Discord's OAuth2 documentation page](https://discord.com/developers/docs/topics/oauth2#shared-resources).
The default scope is **identify**, meaning you will only ensure the user is a valid Discord user, and will receive its ID only.
If you require any other information, you will need to parametrized the scope used.

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

Note: by default, the email retrieved and forwarded by oauth2-proxy will be a dummy email. A valid email can be retrieved
using discord, but requires a specific scope. Please refer to
[Discord's oauth2 documentation](https://discord.com/developers/docs/topics/oauth2#shared-resources) for more details.