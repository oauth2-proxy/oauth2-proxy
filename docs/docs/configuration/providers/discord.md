---
id: discord
title: Discord
---

## Config Options

| Flag                 | Toml Field          | Type           | Description                                              | Default |
| -------------------- | ------------------- | -------------- | -------------------------------------------------------- | ------- |
| `--discord-guild-id` | `discord_guild_ids` | string \| list | restricts logins to members of a specific Discord server |         |

## Usage

Note: On Discord, the terms 'guild' and 'channel' are interchangeable with 'server'.

***Application Setup***
1.  Create a new Discord App from https://discord.com/developers/applications/
    * The Application Name will be what appears when users attempt to authenticate.
2.  On the left hand side of the application information page, navigate to "OAuth2".
3.  On this page, keep track of the Client ID and reset the Client Secret to generate a new secret.
4.  Under Redirects, add your Valid OAuth redirect URIs to `https://<proxied host>oauth2/callback`

***Getting Discord Guild IDs***

The Discord provider only supports Guild IDs and not names because Discord does not require Guild names to be unique.

* **Option 1:** 
    1. In the Discord application or website, navigate to `User Settings -> Advanced` and enable `Developer Mode`.
    2. Right click the Server you wish to get the guild ID for and click the option `Copy Server ID`.
* **Option 2:**
    1. On the discord website, navigate to the server you wish to get the guild ID for.
    2. The URL in the web bar should be formatted as `https://discord.com/channels/<guild_id>/<channel_id>`

To use the provider, pass the following options:

```
   --provider=discord
   --client-id=<Client ID from Step 3>
   --client-secret=<Client Secret from Step 3>
   --discord-guild-id=<guild_id> 
```

The `--discord-guild-id` arg can be specified multiple times with different guild IDs to allow multiple guilds 
to authenticate.