---
layout: default
title: Endpoints
permalink: /endpoints
nav_order: 5
---

## Endpoint Documentation

OAuth2 Proxy responds directly to the following endpoints. All other endpoints will be proxied upstream when authenticated. The `/oauth2` prefix can be changed with the `--proxy-prefix` config variable.

- /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
- /ping - returns a 200 OK response, which is intended for use with health checks
- /oauth2/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
- /oauth2/start - a URL that will redirect to start the OAuth cycle
- /oauth2/callback - the URL used at the end of the OAuth cycle. The oauth app will be configured with this as the callback url.
- /oauth2/userinfo - the URL is used to return user's email from the session in JSON format.
- /oauth2/auth - only returns a 202 Accepted response or a 401 Unauthorized response; for use with the [Nginx `auth_request` directive](#nginx-auth-request)
