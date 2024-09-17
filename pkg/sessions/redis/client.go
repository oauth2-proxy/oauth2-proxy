package redis

import (
	"context"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/redis/go-redis/v9"
)

// Client is wrapper interface for redis.Client and redis.ClusterClient.
type Client interface {
	Get(ctx context.Context, key string) ([]byte, error)
	GetSet(ctx context.Context, key string, value []byte) ([]byte, error)
	Lock(key string) sessions.Lock
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	Del(ctx context.Context, key string) error
	Ping(ctx context.Context) error
}

var _ Client = (*client)(nil)

type client struct {
	*redis.Client
}

func newClient(c *redis.Client) Client {
	return &client{
		Client: c,
	}
}

func (c *client) Get(ctx context.Context, key string) ([]byte, error) {
	return c.Client.Get(ctx, key).Bytes()
}

func (c *client) GetSet(ctx context.Context, key string, value []byte) ([]byte, error) {
	cmd := c.Client.GetSet(ctx, key, value)
	return cmd.Bytes()
}

func (c *client) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.Client.Set(ctx, key, value, expiration).Err()
}

func (c *client) Del(ctx context.Context, key string) error {
	return c.Client.Del(ctx, key).Err()
}

func (c *client) Lock(key string) sessions.Lock {
	return NewLock(c.Client, key)
}

func (c *client) Ping(ctx context.Context) error {
	return c.Client.Ping(ctx).Err()
}

var _ Client = (*clusterClient)(nil)

type clusterClient struct {
	*redis.ClusterClient
}

func newClusterClient(c *redis.ClusterClient) Client {
	return &clusterClient{
		ClusterClient: c,
	}
}

func (c *clusterClient) Get(ctx context.Context, key string) ([]byte, error) {
	return c.ClusterClient.Get(ctx, key).Bytes()
}

func (c *clusterClient) GetSet(ctx context.Context, key string, value []byte) ([]byte, error) {
	return c.ClusterClient.GetSet(ctx, key, value).Bytes()
}

func (c *clusterClient) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.ClusterClient.Set(ctx, key, value, expiration).Err()
}

func (c *clusterClient) Del(ctx context.Context, key string) error {
	return c.ClusterClient.Del(ctx, key).Err()
}

func (c *clusterClient) Lock(key string) sessions.Lock {
	return NewLock(c.ClusterClient, key)
}

func (c *clusterClient) Ping(ctx context.Context) error {
	return c.ClusterClient.Ping(ctx).Err()
}
