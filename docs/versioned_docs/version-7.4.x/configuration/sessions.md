---
id: session_storage
title: Session Storage
---

Sessions allow a user's authentication to be tracked between multiple HTTP
requests to a service.

The OAuth2 Proxy uses a Cookie to track user sessions and will store the session
data in one of the available session storage backends.

At present the available backends are (as passed to `--session-store-type`):
- [cookie](#cookie-storage) (default)
- [redis](#redis-storage)

### Cookie Storage

The Cookie storage backend is the default backend implementation and has
been used in the OAuth2 Proxy historically.

With the Cookie storage backend, all session information is stored in client
side cookies and transferred with each and every request.

The following should be known when using this implementation:
- Since all state is stored client side, this storage backend means that the OAuth2 Proxy is completely stateless
- Cookies are signed server side to prevent modification client-side
- It is mandatory to set a `cookie-secret` which will ensure data is encrypted within the cookie data.
- Since multiple requests can be made concurrently to the OAuth2 Proxy, this session implementation
cannot lock sessions and while updating and refreshing sessions, there can be conflicts which force
users to re-authenticate


### Redis Storage

The Redis Storage backend stores sessions, encrypted, in redis. Instead sending all the information
back the client for storage, as in the [Cookie storage](#cookie-storage), a ticket is sent back
to the user as the cookie value instead.

A ticket is composed as the following:

`{CookieName}-{ticketID}.{secret}`

Where:

- The `CookieName` is the OAuth2 cookie name (_oauth2_proxy by default)
- The `ticketID` is a 128 bit random number, hex-encoded
- The `secret` is a 128 bit random number, base64url encoded (no padding). The secret is unique for every session.
- The pair of `{CookieName}-{ticketID}` comprises a ticket handle, and thus, the redis key
to which the session is stored. The encoded session is encrypted with the secret and stored
in redis via the `SETEX` command.

Encrypting every session uniquely protects the refresh/access/id tokens stored in the session from
disclosure.

#### Usage

When using the redis store, specify `--session-store-type=redis` as well as the Redis connection URL, via
`--redis-connection-url=redis://host[:port][/db-number]`.

You may also configure the store for Redis Sentinel. In this case, you will want to use the
`--redis-use-sentinel=true` flag, as well as configure the flags `--redis-sentinel-master-name`
and `--redis-sentinel-connection-urls` appropriately.

Redis Cluster is available to be the backend store as well. To leverage it, you will need to set the
`--redis-use-cluster=true` flag, and configure the flags `--redis-cluster-connection-urls` appropriately.

Note that flags `--redis-use-sentinel=true` and `--redis-use-cluster=true` are mutually exclusive.

Note, if Redis timeout option is set to non-zero, the `--redis-connection-idle-timeout` 
must be less than [Redis timeout option](https://redis.io/docs/reference/clients/#client-timeouts). For example: if either redis.conf includes 
`timeout 15` or using `CONFIG SET timeout 15` the `--redis-connection-idle-timeout` must be at least `--redis-connection-idle-timeout=14`