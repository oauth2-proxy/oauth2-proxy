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

	group singleflight.Group
}

func newClient(c *redis.Client) Client {
	return &client{Client: c}
}

func (c *client) Get(ctx context.Context, key string) ([]byte, error) {
	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		b, err := c.WithContext(ctx).Get(key).Bytes()
		if err != nil {
			return nil, err
		}
		return b, nil
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

func (c *client) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	_, err, _ := c.group.Do(key, func() (interface{}, error) {
		return nil, c.WithContext(ctx).Set(key, value, expiration).Err()
	})
	return err
}

func (c *client) Del(ctx context.Context, key string) error {
	_, err, _ := c.group.Do(key, func() (interface{}, error) {
		return nil, c.WithContext(ctx).Del(key).Err()
	})
	return err
}

var _ Client = (*clusterClient)(nil)

type clusterClient struct {
	*redis.ClusterClient

	group singleflight.Group
}

func newClusterClient(c *redis.ClusterClient) Client {
	return &clusterClient{ClusterClient: c}
}

func (c *clusterClient) Get(ctx context.Context, key string) ([]byte, error) {
	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		b, err := c.WithContext(ctx).Get(key).Bytes()
		if err != nil {
			return nil, err
		}
		return b, nil
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

func (c *clusterClient) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	_, err, _ := c.group.Do(key, func() (interface{}, error) {
		return nil, c.WithContext(ctx).Set(key, value, expiration).Err()
	})
	return err
}

func (c *clusterClient) Del(ctx context.Context, key string) error {
	_, err, _ := c.group.Do(key, func() (interface{}, error) {
		return nil, c.WithContext(ctx).Del(key).Err()
	})
	return err
}
