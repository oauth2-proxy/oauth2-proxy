package redis

import (
	"context"
	"fmt"
	"github.com/bsm/redislock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"time"
)

type Lock struct {
	locker *redislock.Client
	lock   *redislock.Lock
	key    string
}

func NewLock(lockClient *redislock.Client, key string) sessions.Lock {
	return &Lock{
		locker: lockClient,
		key:    key,
	}
}

func (l *Lock) Obtain(ctx context.Context, expiration time.Duration) error {
	lock, err := l.locker.Obtain(ctx, fmt.Sprintf("lock.%s", l.key), expiration, nil)
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
	// we need to figure out how to do this
	return false, nil
}

func (l *Lock) Release(ctx context.Context) error {
	if l.lock == nil {
		return fmt.Errorf("tried to release not existing lock")
	}
	return l.lock.Release(ctx)
}
