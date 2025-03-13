package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
)

func TestRedisStore_Create(t *testing.T) {
	tests := []struct {
		name         string
		mockCreate   func(ctx context.Context, id string, providerConfig []byte) error
		id           string
		providerConf []byte
		wantErr      bool
	}{
		{
			"provider config create successsful",
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			"t1",
			[]byte("xxx"),
			false,
		},
		{
			"provider config create not successsful due to redis error",
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			"",
			[]byte("xxx"),
			true,
		},
		{
			"provider config create not successful due to postgres error",
			func(ctx context.Context, id string, providerConfig []byte) error {
				return fmt.Errorf("error")
			},
			"t1",
			[]byte("xxx"),
			true,
		},
	}

	s := miniredis.RunT(t)
	rdb, _ := redis.NewRedisClient(options.RedisStoreOptions{
		ConnectionURL: "redis://" + s.Addr(),
		Password:      "",
	})

	for _, test := range tests {
		if test.wantErr {
			s.SetError("error")
		}

		ctx := context.Background()
		c := &RedisStore{
			configStore: fakeConfigStore{
				CreateFunc: test.mockCreate,
			},
			rdb: rdb,
			redisOptions: &options.Redis{
				Prefix: "abc",
			},
		}
		err := c.Create(ctx, test.id, test.providerConf)
		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Create provider config expectedError = %v, gotError = '%v'", test.wantErr, err)
		}

	}

}

func TestRedisStore_Update(t *testing.T) {
	tests := []struct {
		name         string
		mockUpdate   func(ctx context.Context, id string, providerConfig []byte) error
		id           string
		providerConf []byte
		wantErr      bool
	}{
		{
			"provider config update successsful",
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			"t1",
			[]byte("xxx"),
			false,
		},
		{
			"provider config update not successsful due to redis error",
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			"",
			[]byte("xxx"),
			true,
		},
		{
			"provider config update not successful due to postgres error",
			func(ctx context.Context, id string, providerConfig []byte) error {
				return fmt.Errorf("error")
			},
			"t1",
			[]byte("xxx"),
			true,
		},
	}

	s := miniredis.RunT(t)
	rdb, _ := redis.NewRedisClient(options.RedisStoreOptions{
		ConnectionURL: "redis://" + s.Addr(),
		Password:      "",
	})

	for _, test := range tests {
		if test.wantErr {
			s.SetError("error")
		}

		ctx := context.Background()
		c := &RedisStore{
			configStore: fakeConfigStore{
				UpdateFunc: test.mockUpdate,
			},
			rdb: rdb,
			redisOptions: &options.Redis{
				Prefix: "abc",
			},
		}
		err := c.Update(ctx, test.id, test.providerConf)
		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Update provider config expectedError = %v, gotError = '%v'", test.wantErr, err)
		}

	}

}

func TestRedisStore_Get(t *testing.T) {
	tests := []struct {
		name         string
		mockGet      func(ctx context.Context, id string) (string, error)
		id           string
		providerConf string
		expiry       time.Duration
		wantErr      bool
	}{
		{
			"provider config get successsful from redis",
			func(ctx context.Context, id string) (string, error) {
				return "", nil
			},
			"t1",
			"xxx",
			time.Duration(5 * time.Second),
			false,
		},
		{
			"provider config get not successful from redis",
			func(ctx context.Context, id string) (string, error) {
				return "", fmt.Errorf("error")
			},
			"",
			"",
			time.Duration(1 * time.Nanosecond),
			true,
		},
		{
			"provider config get successful from postgres",
			func(ctx context.Context, id string) (string, error) {
				if id == "t1" {
					return "xxx", nil
				}
				return "", nil
			},
			"t1",
			"xxx",
			time.Duration(1 * time.Nanosecond),
			false,
		},
		{
			"provider config get not successful from postgres",
			func(ctx context.Context, id string) (string, error) {
				return "", fmt.Errorf("error")
			},
			"t1",
			"",
			time.Duration(1 * time.Nanosecond),
			true,
		},
	}

	s := miniredis.RunT(t)

	rdb, _ := redis.NewRedisClient(options.RedisStoreOptions{
		ConnectionURL: "redis://" + s.Addr(),
		Password:      "",
	})

	for _, test := range tests {
		s.Set("abc-t1", "xxx")
		s.SetTTL("abc-t1", test.expiry)
		s.FastForward(11 * time.Nanosecond)

		ctx := context.Background()
		c := &RedisStore{
			configStore: fakeConfigStore{
				GetFunc: test.mockGet,
			},
			rdb: rdb,
			redisOptions: &options.Redis{
				Prefix: "abc",
				Expiry: test.expiry,
			},
		}
		val, err := c.Get(ctx, test.id)
		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Get provider config expectedError = %v, gotError = '%v'", test.wantErr, err)
		}
		if val != test.providerConf {
			t.Errorf("Get provider config returned config: %s, wanted %s", val, test.providerConf)
		}

	}

}

func TestRedisStore_Delete(t *testing.T) {
	tests := []struct {
		name       string
		mockDelete func(ctx context.Context, id string) error
		id         string
		wantErr    bool
	}{
		{
			"provider config delete successsful",
			func(ctx context.Context, id string) error {
				return nil
			},
			"t1",
			false,
		},
		{
			"provider config delete not successsful due to redis error",
			func(ctx context.Context, id string) error {
				return nil
			},
			"",
			true,
		},
		{
			"provider config delete not successful due to postgres error",
			func(ctx context.Context, id string) error {
				return fmt.Errorf("error")
			},
			"t1",
			true,
		},
	}

	s := miniredis.RunT(t)
	rdb, _ := redis.NewRedisClient(options.RedisStoreOptions{
		ConnectionURL: "redis://" + s.Addr(),
		Password:      "",
	})

	for _, test := range tests {
		if test.wantErr {
			s.SetError("error")
		}

		ctx := context.Background()
		c := &RedisStore{
			configStore: fakeConfigStore{
				DeleteFunc: test.mockDelete,
			},
			rdb: rdb,
			redisOptions: &options.Redis{
				Prefix: "abc",
			},
		}
		err := c.Delete(ctx, test.id)
		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Delete provider config  expectedError = %v, gotError = '%v'", test.wantErr, err)
		}

	}

}
