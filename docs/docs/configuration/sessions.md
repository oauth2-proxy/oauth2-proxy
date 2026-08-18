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
- [http](#http-storage)

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

### HTTP Storage

The HTTP Storage backend stores encrypted sessions on a remote server via a REST API. Like the [Redis storage](#redis-storage),
a ticket is sent back to the user as the cookie value instead of the entire session data.

The ticket format is the same as Redis storage:

`{CookieName}-{ticketID}.{secret}`

Where:

- The `CookieName` is the OAuth2 cookie name (_oauth2_proxy by default)
- The `ticketID` is a 128-bit random number, hex-encoded
- The `secret` is a 128-bit random number, base64url encoded (no padding). The secret is unique for every session.
- The pair of `{CookieName}-{ticketID}` comprises a ticket handle, and thus, the session key

The session is encrypted with the secret and sent to the HTTP storage backend for storage.

#### Usage

When using the HTTP store, specify `--session-store-type=http` as well as the HTTP storage backend URL, via
`--http-store-base-url=https://your-storage-backend.example.com`.

Optionally, you can provide an API key for authentication using `--http-store-api-key=your-secret-api-key`.

Example configuration:
```
--session-store-type=http
--http-store-base-url=https://session-store.example.com
--http-store-api-key=mysecretapikey123
```

#### REST API Specification

The HTTP storage backend must implement the following REST API.

##### Authentication

All requests include an `Authorization` header with a Bearer token if an API key is configured:
```
Authorization: Bearer {api-key}
```

##### Endpoints

**1. Save Session**

Stores or updates a session with the given key and TTL.

```
PUT /sessions/{key}
Content-Type: application/json

{
  "data": "base64-encoded-encrypted-session-data",
  "ttl_seconds": 3600
}
```

Response:
- `200 OK` or `201 Created` on success
- `4xx` or `5xx` on error

**2. Load Session**

Retrieves a session by key.

```
GET /sessions/{key}
```

Response:
- `200 OK` with JSON body on success:
  ```json
  {
    "data": "base64-encoded-encrypted-session-data"
  }
  ```
- `404 Not Found` if session does not exist
- `4xx` or `5xx` on error

**3. Clear Session**

Deletes a session by key.

```
DELETE /sessions/{key}
```

Response:
- `200 OK` or `204 No Content` on success
- `404 Not Found` if session does not exist (also treated as success)
- `4xx` or `5xx` on error

**4. Health Check**

Verifies that the storage backend is accessible and healthy.

```
GET /health
```

Response:
- `200 OK` if the backend is healthy
- `5xx` on error

#### Implementation Notes

- Session data is already encrypted by oauth2-proxy before being sent to the HTTP storage backend
- The `key` parameter in the URL is the session ticket handle: `{CookieName}-{ticketID}`
- The HTTP storage backend should respect the `ttl_seconds` parameter and automatically expire sessions after this duration
- The HTTP client has a 30-second timeout for all requests
- Distributed locking is not currently supported with the HTTP storage backend

#### Example Backend Implementation

Here's a simple example of an HTTP storage backend using Python and Flask:

```python
from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# In-memory storage (use Redis, database, etc. in production)
sessions = {}
API_KEY = "mysecretapikey123"

def check_auth():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return False
    return auth[7:] == API_KEY

@app.route('/health')
def health():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"status": "healthy"}), 200

@app.route('/sessions/<key>', methods=['PUT'])
def save_session(key):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401

    data = request.json
    sessions[key] = {
        'data': data['data'],
        'expires_at': time.time() + data['ttl_seconds']
    }
    return jsonify({"status": "ok"}), 200

@app.route('/sessions/<key>', methods=['GET'])
def load_session(key):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401

    if key not in sessions:
        return jsonify({"error": "not found"}), 404

    session = sessions[key]
    if time.time() > session['expires_at']:
        del sessions[key]
        return jsonify({"error": "not found"}), 404

    return jsonify({"data": session['data']}), 200

@app.route('/sessions/<key>', methods=['DELETE'])
def clear_session(key):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401

    if key in sessions:
        del sessions[key]
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```
