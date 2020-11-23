package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

// Client is wrapper interface for redis.Client and redis.ClusterClient.
type Client interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	Del(ctx context.Context, key string) error
}

var _ Client = (*client)(nil)

type client struct {
	*redis.Client
}

func newClient(c *redis.Client) Client {
	return &client{Client: c}
}

func (c *client) Get(ctx context.Context, key string) ([]byte, error) {
	return c.Client.Get(ctx, key).Bytes()
}

func (c *client) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.Client.Set(ctx, key, value, expiration).Err()
}

func (c *client) Del(ctx context.Context, key string) error {
	return c.Client.Del(ctx, key).Err()
}

var _ Client = (*clusterClient)(nil)

type clusterClient struct {
	*redis.ClusterClient
}

func newClusterClient(c *redis.ClusterClient) Client {
	return &clusterClient{ClusterClient: c}
}

func (c *clusterClient) Get(ctx context.Context, key string) ([]byte, error) {
	return c.ClusterClient.Get(ctx, key).Bytes()
}

func (c *clusterClient) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.ClusterClient.Set(ctx, key, value, expiration).Err()
}

func (c *clusterClient) Del(ctx context.Context, key string) error {
	return c.ClusterClient.Del(ctx, key).Err()
}
