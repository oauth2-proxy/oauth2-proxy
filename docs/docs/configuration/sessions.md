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
- [sqlite](#sqlite-storage) (multiple instances, single host only)

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


### SQLite Storage

SQLite stores encrypted sessions in a local database and sends the browser the same
short, signed ticket used by the Redis backend. Tokens stay server-side. Large tokens
therefore do not cause split session cookies, including when using Nginx `auth_request`.
Cookie storage remains the default; no existing deployments need to migrate.

```text
--session-store-type=sqlite
--sqlite-path=/var/lib/oauth2-proxy/sessions.sqlite
```

The path must be absolute. Create the parent directory with permissions that allow
only the OAuth2 Proxy user to access it. The process must be able to write both the
database and its `-wal` and `-shm` sidecar files. New databases have mode `0600`;
administrators must restrict permissions on existing files and backups.

**Multiple instances are supported, but always on a single host.** All instances
must share the same database on a local filesystem and use the same cookie secret
and compatible authentication settings. Mount the whole directory into containers,
not just the database file. Do not use network filesystems (including NFS), or share
the database across hosts. Use Redis for multi-host deployments.

On first startup, instances coordinate schema creation through a database write
transaction, retrying temporary contention for up to ten seconds. Subsequent
starts read the schema version without taking a schema write lock. A database
with a newer, unsupported schema version is rejected rather than modified.

SQLite WAL mode allows concurrent readers but only one writer at a time. Writes
wait up to five seconds for contention. Short database leases coordinate session
refreshes across processes without holding a write transaction during provider
requests. This backend is intended for deployments whose session-write volume fits
a single host, not as a distributed replacement for Redis.

`--cookie-expire` and `--cookie-refresh` have the same meaning as with Redis.
Expired sessions are rejected on reads; writes reclaim expired rows in bounded
batches. Idle databases can retain expired, encrypted records until another write.
Database errors do not authenticate a request. Keep a persistent volume across
restarts; losing the database, or changing from another storage backend, requires
users to sign in again. Use SQLite-aware backup tools rather than copying a live
database file without its WAL.

### Redis Storage

The Redis Storage backend stores encrypted sessions in redis. Instead of sending all the information
back the client for storage, as in the [Cookie storage](#cookie-storage), a ticket is sent back
to the user as the cookie value instead.

A ticket is composed as the following:

`{CookieName}-{ticketID}.{secret}`

Where:

- The `CookieName` is the OAuth2 cookie name (_oauth2_proxy by default)
- The `ticketID` is a 128-bit random number, hex-encoded
- The `secret` is a 128-bit random number, base64url encoded (no padding). The secret is unique for every session.
- The pair of `{CookieName}-{ticketID}` comprises a ticket handle, and thus, the redis key
to which the session is stored. The encoded session is encrypted with the secret and stored
in redis via the `SETEX` command.

Encrypting every session uniquely protects the refresh/access/id tokens stored in the session from
disclosure. Additionally, the browser only has to send a short Cookie with every request and not the whole JWT, 
which can get quite big.

Two settings are used to configure the OAuth2 Proxy cookie lifetime:

    --cookie-refresh duration   refresh the cookie after this duration; 0 to disable
    --cookie-expire duration    expire timeframe for cookie     168h0m0s

The "cookie-expire" value should be equal to the lifetime of the Refresh-Token that is issued by the OAuth2 authorization server.
If it expires earlier and is deleted by the browser, OAuth2 Proxy cannot find the stored Refresh-Tokens in Redis and thus cannot start
the refresh flow to get a new Access-Token. If it is longer, it might be that the old Refresh-Token will be found in Redis but has already
expired.

The "cookie-refresh" value controls when OAuth2 Proxy tries to refresh an Access-Token. If it is set to "0", the
Access-Token will never be refreshed, even if it is already expired and a valid Refresh-Token is available. If set, OAuth2 Proxy will
refresh the Access-Token after this many seconds whether it is still valid or not. According to the official OAuth2.0 specification 
Access-Tokens are not required to follow a specific format. Therefore OAuth2 Proxy cannot check for any expiry date without an 
introspection endpoint. If an Access-Token expires and you have not set a corresponding "cookie-refresh" value, you will likely 
encounter expiry issues.

Caveat: It can happen that the Access-Token is valid for e.g. "1m" and a request happens after exactly "59s".
It would pass OAuth2 Proxy and be forwarded to the backend but is just expired when the backend tries to validate
it. This is especially relevant if the backend uses the JWT to make requests to other backends.
For this reason, it's advised to set the cookie-refresh a couple of seconds less than the Access-Token lifespan.

Recommended settings:

* cookie_refresh := Access-Token lifespan - 1m
* cookie_expire := Refresh-Token lifespan (i.e. Keycloak client_session_idle)

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
