package dpop

import (
	"context"
	"time"
)

// RedisClient defines the subset of redis commands used by RedisDpopStore.
// This allows for easier mocked testing or using different redis implementations.
type RedisClient interface {
	SetNX(ctx context.Context, key string, value []byte, expiration time.Duration) (bool, error)
}

// RedisDpopStore is a Redis-backed implementation of the DpopStore interface.
// It is intended for scalable, multi-instance deployments.
type RedisDpopStore struct {
	client    RedisClient
	jtiPrefix string
}

// NewRedisDpopStore creates a new Redis DpopStore.
func NewRedisDpopStore(client RedisClient) *RedisDpopStore {
	return &RedisDpopStore{
		client:    client,
		jtiPrefix: "dpop:jti:",
	}
}

// MarkJtiSeen checks if a JTI scoped by JKT has been seen by checking if it exists in Redis.
// It relies on Redis's SetNX (Set if Not eXists) command to atomically check and set.
// It returns true if the JTI was successfully inserted (it was not seen before).
// It returns false if the JTI was already present (it has been seen).
func (c *RedisDpopStore) MarkJtiSeen(ctx context.Context, jkt string, jti string, expiresAt time.Time) (bool, error) {
	key := c.jtiPrefix + jkt + ":" + jti
	ttl := time.Until(expiresAt)

	// If the expiration time is already in the past, we shouldn't even store it,
	// or we can store it with a minimal TTL. However, the validator should
	// have already rejected it if iat was too old.
	if ttl <= 0 {
		return false, nil // Already expired
	}

	// SetNX will return true if the key didn't exist and was set.
	// It will return false if the key already existed.
	res, err := c.client.SetNX(ctx, key, []byte("1"), ttl)
	if err != nil {
		return false, err
	}

	return res, nil
}
