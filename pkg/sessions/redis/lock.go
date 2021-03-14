package redis

import (
	"context"
	"fmt"
	"github.com/bsm/redislock"
	"github.com/go-redis/redis/v8"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"time"
)

type Lock struct {
	client redis.Cmdable
	locker *redislock.Client
	lock   *redislock.Lock
	key    string
}

func NewLock(client redis.Cmdable, key string) sessions.Lock {
	return &Lock{
		client: client,
		locker: redislock.New(client),
		key:    key,
	}
}

func (l *Lock) Obtain(ctx context.Context, expiration time.Duration) error {
	lock, err := l.locker.Obtain(ctx, fmt.Sprintf("lock.%s", l.key), expiration, nil)
	if err == redislock.ErrNotObtained {
		return sessions.ErrLockNotObtained
	}
	if err != nil {
		return err
	}
	l.lock = lock
	return nil
}

func (l *Lock) Refresh(ctx context.Context, expiration time.Duration) error {
	if l.lock == nil {
		return fmt.Errorf("tried to refresh not existing lock")
	}
	return l.lock.Refresh(ctx, expiration, nil)
}

func (l *Lock) Peek(ctx context.Context) (bool, error) {
	v, err := l.client.Get(ctx, l.key).Bytes()
	if err != nil {
		return false, err
	}
	if v != nil {
		return true, nil
	}
	return false, nil
}

func (l *Lock) Release(ctx context.Context) error {
	if l.lock == nil {
		return fmt.Errorf("tried to release not existing lock")
	}
	return l.lock.Release(ctx)
}
