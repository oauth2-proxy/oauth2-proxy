---
layout: default
title: Home
permalink: /
nav_order: 0
---

![OAuth2 Proxy](/logos/OAuth2_Proxy_horizontal.svg)

A reverse proxy and static file server that provides authentication using Providers (Google, GitHub, and others)
to validate accounts by email, domain or group.

**Note:** This repository was forked from [bitly/OAuth2_Proxy](https://github.com/bitly/oauth2_proxy) on 27/11/2018.
Versions v3.0.0 and up are from this fork and will have diverged from any changes in the original fork.
A list of changes can be seen in the [CHANGELOG]({{ site.gitweb }}/CHANGELOG.md).

[![Build Status](https://secure.travis-ci.org/oauth2-proxy/oauth2-proxy.svg?branch=master)](http://travis-ci.org/oauth2-proxy/oauth2-proxy)

![Sign In Page](https://cloud.githubusercontent.com/assets/45028/4970624/7feb7dd8-6886-11e4-93e0-c9904af44ea8.png)

## Architecture

![OAuth2 Proxy Architecture](https://cloud.githubusercontent.com/assets/45028/8027702/bd040b7a-0d6a-11e5-85b9-f8d953d04f39.png)

## Behavior

1. Any request passing through the proxy (and not matched by `--skip-auth-regex`) is checked for the proxy's session cookie (`--cookie-name`) (or, if allowed, a JWT token - see `--skip-jwt-bearer-tokens`). 
2. If authentication is required but missing then the user is asked to log in and redirected to the authentication provider (unless it is an Ajax request, i.e. one with `Accept: application/json`, in which case 401 Unauthorized is returned)
3. After returning from the authentication provider, the oauth tokens are stored in the configured session store (cookie, redis, ...) and a cookie is set
4. The request is forwarded to the upstream server with added user info and authentication headers (depending on the configuration)

Notice that the proxy alos provides a number of useful [endpoints](/oauth2-proxy/endpoints)
