package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v7"
	"golang.org/x/sync/singleflight"
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
	return get(c.WithContext(ctx), key)
}

func (c *client) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return set(c.WithContext(ctx), key, value, expiration)
}

func (c *client) Del(ctx context.Context, key string) error {
	return del(c.WithContext(ctx), key)
}

var _ Client = (*clusterClient)(nil)

type clusterClient struct {
	*redis.ClusterClient
}

func newClusterClient(c *redis.ClusterClient) Client {
	return &clusterClient{ClusterClient: c}
}

func (c *clusterClient) Get(ctx context.Context, key string) ([]byte, error) {
	return get(c.WithContext(ctx), key)
}

func (c *clusterClient) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return set(c.WithContext(ctx), key, value, expiration)
}

func (c *clusterClient) Del(ctx context.Context, key string) error {
	return del(c.WithContext(ctx), key)
}

type getter interface {
	Get(key string) *redis.StringCmd
}

var group singleflight.Group

func get(cmd getter, key string) ([]byte, error) {
	v, err, _ := group.Do(key, func() (interface{}, error) {
		return cmd.Get(key).Bytes()
	})
	if err != nil {
		return nil, err
	}

	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid value type: key=%s, value%v", key, v)
	}
	return b, nil
}

type setter interface {
	Set(key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

func set(cmd setter, key string, value []byte, expiration time.Duration) error {
	_, err, _ := group.Do(key, func() (interface{}, error) {
		return nil, cmd.Set(key, value, expiration).Err()
	})
	return err
}

type deleter interface {
	Del(keys ...string) *redis.IntCmd
}

func del(cmd deleter, key string) error {
	_, err, _ := group.Do(key, func() (interface{}, error) {
		return nil, cmd.Del(key).Err()
	})
	return err
}
