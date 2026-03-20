---
id: dpop
title: DPoP
---

OAuth2-Proxy supports **Demonstrating Proof of Possession (DPoP)** at the application level, as defined in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

DPoP is a mechanism that allows a client to prove possession of a private key by signing a JWT (DPoP Proof) and including it in the request. This binds the access token to the client's key, preventing token replay if intercepted.

## Implementation Details

- **Spec Support**: [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
- **Library**: JWT parsing and signature verification are handled by [go-jose](https://github.com/go-jose/go-jose).
- **JTI Storage**: To prevent replay attacks, the JTI (JWT ID) from the DPoP proof is stored for the duration of the time window.

## Configuration

Enable DPoP support and configure the JTI store using the following flags:

| Flag                    | Description                                                        | Default   |
| ----------------------- | ------------------------------------------------------------------ | --------- |
| `--enable-dpop-support` | Enable verification of DPoP structured tokens.                     | `false`   |
| `--dpop-time-window`    | The acceptable time window for DPoP proof's `iat` claim.           | `5m`      |
| `--dpop-jti-store-type` | The type of JTI store to use (`memory`, `redis`, `session-redis`). | `memory`* |

> [!NOTE]
> *The default for `--dpop-jti-store-type` is dynamic. If your session store is set to `redis` and you don't explicitly set a JTI store type, it will automatically use `session-redis`.

### Redis Session Integration (`session-redis`)

The `session-redis` store type allows DPoP to reuse the existing Redis configuration used for sessions. This is the recommended configuration when using Redis sessions as it requires no additional DPoP-specific Redis flags.

```bash
# Example configuration for Redis sessions with automatic DPoP JTI storage
oauth2-proxy \
  --session-store-type=redis \
  --redis-connection-url=redis://localhost:6379 \
  --enable-dpop-support=true
```

### Standalone Redis Storage (`redis`)

If you want to use a separate Redis instance for DPoP JTIs, use the `redis` store type and configure the DPoP-specific Redis flags:

- `--dpop-redis-connection-url`
- `--dpop-redis-password`
- `--dpop-redis-use-sentinel`
- (and other `dpop-redis-*` flags)
