package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bsm/redislock"
	"github.com/go-redis/redis/v8"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

var LockPrefix = "lock"

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
	lock, err := l.locker.Obtain(ctx, l.lockKey(), expiration, nil)
	if errors.Is(err, redislock.ErrNotObtained) {
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
		return sessions.ErrNotLocked
	}
	return l.lock.Refresh(ctx, expiration, nil)
}

func (l *Lock) Peek(ctx context.Context) (bool, error) {
	v, err := l.client.Exists(ctx, l.lockKey()).Result()
	if err != nil {
		return false, err
	}
	if v == 0 {
		return false, nil
	}
	return true, nil
}

func (l *Lock) Release(ctx context.Context) error {
	if l.lock == nil {
		return sessions.ErrNotLocked
	}
	return l.lock.Release(ctx)
}

func (l *Lock) lockKey() string {
	return fmt.Sprintf("%s.%s", LockPrefix, l.key)
}
