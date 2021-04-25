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

// Instantiate a ne lock instance. This will not yet apply a lock on Redis side.
// For that you have to call Obtain(ctx context.Context, expiration time.Duration)
func NewLock(client redis.Cmdable, key string) sessions.Lock {
	return &Lock{
		client: client,
		locker: redislock.New(client),
		key:    key,
	}
}

// Obtain obtains a distributed lock on Redis for the configured key.
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

// Refresh refreshes an already existing lock.
func (l *Lock) Refresh(ctx context.Context, expiration time.Duration) error {
	if l.lock == nil {
		return sessions.ErrNotLocked
	}
	return l.lock.Refresh(ctx, expiration, nil)
}

// Peek returns true, if the lock is still applied.
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

// Release releases the lock on Redis side.
func (l *Lock) Release(ctx context.Context) error {
	if l.lock == nil {
		return sessions.ErrNotLocked
	}
	return l.lock.Release(ctx)
}

func (l *Lock) lockKey() string {
	return fmt.Sprintf("%s.%s", LockPrefix, l.key)
}
