package redis

import (
	"context"
	"time"

	"github.com/bsm/redislock"
	"github.com/go-redis/redis/v8"
)

// Client is wrapper interface for redis.Client and redis.ClusterClient.
type Client interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Lock(ctx context.Context, key string, expiration time.Duration) error
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	Del(ctx context.Context, key string) error
}

var _ Client = (*client)(nil)

type client struct {
	*redis.Client
	locker *redislock.Client
	lock   *redislock.Lock
}

func newClient(c *redis.Client) Client {
	return &client{
		Client: c,
		locker: redislock.New(c),
	}
}

func (c *client) Get(ctx context.Context, key string) ([]byte, error) {
	if c.lock != nil {
		for {
			ttl, err := c.lock.TTL(ctx)
			if err != nil {
				return nil, err
			}
			if ttl <= 0 {
				break
			}
		}
	}
	return c.Client.Get(ctx, key).Bytes()
}

func (c *client) Lock(ctx context.Context, key string, expiration time.Duration) error {
	lock, err := c.locker.Obtain(ctx, key, expiration, nil)
	if err != nil {
		return err
	}
	c.lock = lock
	return nil
}

func (c *client) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	err := c.Client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return err
	}
	if c.lock == nil {
		return nil
	}
	err = c.lock.Release(ctx)
	if err != nil {
		return err
	}
	c.lock = nil
	return nil
}

func (c *client) Del(ctx context.Context, key string) error {
	return c.Client.Del(ctx, key).Err()
}

var _ Client = (*clusterClient)(nil)

type clusterClient struct {
	*redis.ClusterClient
	locker *redislock.Client
	lock   *redislock.Lock
}

func newClusterClient(c *redis.ClusterClient) Client {
	return &clusterClient{
		ClusterClient: c,
		locker:        redislock.New(c),
	}
}

func (c *clusterClient) Get(ctx context.Context, key string) ([]byte, error) {
	return c.ClusterClient.Get(ctx, key).Bytes()
}

func (c *clusterClient) Lock(ctx context.Context, key string, expiration time.Duration) error {
	lock, err := c.locker.Obtain(ctx, key, expiration, nil)
	if err != nil {
		return err
	}
	c.lock = lock
	return nil
}

func (c *clusterClient) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.ClusterClient.Set(ctx, key, value, expiration).Err()
}

func (c *clusterClient) Del(ctx context.Context, key string) error {
	return c.ClusterClient.Del(ctx, key).Err()
}
