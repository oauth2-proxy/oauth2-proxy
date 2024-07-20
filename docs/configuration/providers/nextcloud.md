---
id: nextcloud
title: NextCloud
---

The Nextcloud provider allows you to authenticate against users in your
Nextcloud instance.

When you are using the Nextcloud provider, you must specify the urls via
configuration, environment variable, or command line argument. Depending
on whether your Nextcloud instance is using pretty urls your urls may be of the
form `/index.php/apps/oauth2/*` or `/apps/oauth2/*`.

Refer to the [OAuth2
documentation](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/oauth2.html)
to set up the client id and client secret. Your "Redirection URI" will be
`https://internalapp.yourcompany.com/oauth2/callback`.

```
    -provider nextcloud
    -client-id <from nextcloud admin>
    -client-secret <from nextcloud admin>
    -login-url="<your nextcloud url>/index.php/apps/oauth2/authorize"
    -redeem-url="<your nextcloud url>/index.php/apps/oauth2/api/v1/token"
    -validate-url="<your nextcloud url>/ocs/v2.php/cloud/user?format=json"
```

Note: in *all* cases the validate-url will *not* have the `index.php`.
