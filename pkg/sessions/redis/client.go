package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/bsm/redislock"
	"github.com/go-redis/redis/v8"
)

// Client is wrapper interface for redis.Client and redis.ClusterClient.
type Client interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Lock(ctx context.Context, key string, expiration time.Duration) error
	Unlock(ctx context.Context, key string) error
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	Del(ctx context.Context, key string) error
}

var _ Client = (*client)(nil)

type client struct {
	*redis.Client
	locker *redislock.Client
	locks  map[string]*redislock.Lock
}

func newClient(c *redis.Client) Client {
	return &client{
		Client: c,
		locker: redislock.New(c),
		locks:  map[string]*redislock.Lock{},
	}
}

func (c *client) Get(ctx context.Context, key string) ([]byte, error) {
	return c.Client.Get(ctx, key).Bytes()
}

func (c *client) Lock(ctx context.Context, key string, expiration time.Duration) error {
	if c.locks[key] != nil {
		return fmt.Errorf("lock for key %s already exists", key)
	}
	lock, err := c.locker.Obtain(ctx, key, expiration, nil)
	if err != nil {
		return err
	}
	c.locks[key] = lock
	return nil
}

func (c *client) Unlock(ctx context.Context, key string) error {
	if c.locks[key] == nil {
		return nil
	}
	err := c.locks[key].Release(ctx)
	delete(c.locks, key)
	return err
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
	locker *redislock.Client
	locks  map[string]*redislock.Lock
}

func newClusterClient(c *redis.ClusterClient) Client {
	return &clusterClient{
		ClusterClient: c,
		locker:        redislock.New(c),
		locks:         map[string]*redislock.Lock{},
	}
}

func (c *clusterClient) Get(ctx context.Context, key string) ([]byte, error) {
	return c.ClusterClient.Get(ctx, key).Bytes()
}

func (c *clusterClient) Lock(ctx context.Context, key string, expiration time.Duration) error {
	if c.locks[key] != nil {
		return fmt.Errorf("lock for key %s already exists", key)
	}
	lock, err := c.locker.Obtain(ctx, key, expiration, nil)
	if err != nil {
		return err
	}
	c.locks[key] = lock
	return nil
}

func (c *clusterClient) Unlock(ctx context.Context, key string) error {
	if c.locks[key] == nil {
		return nil
	}
	err := c.locks[key].Release(ctx)
	delete(c.locks, key)
	return err
}

func (c *clusterClient) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return c.ClusterClient.Set(ctx, key, value, expiration).Err()
}

func (c *clusterClient) Del(ctx context.Context, key string) error {
	return c.ClusterClient.Del(ctx, key).Err()
}
