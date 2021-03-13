package redis

import (
	"fmt"
	"github.com/bsm/redislock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"net/http"
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

func (l *Lock) Obtain(req *http.Request, expiration time.Duration) error {
	ctx := req.Context()
	lock, err := l.locker.Obtain(ctx, l.key, expiration, nil)
	if err != nil {
		return err
	}
	l.lock = lock
	return nil
}

func (l *Lock) Refresh(req *http.Request, expiration time.Duration) error {
	if l.lock == nil {
		return fmt.Errorf("tried to refresh not existing lock")
	}
	return l.lock.Refresh(req.Context(), expiration, nil)
}

func (l *Lock) Peek(req *http.Request) (bool, error) {
	// we need to figure out how to do this
	return false, nil
}

func (l *Lock) Release(req *http.Request) error {
	if l.lock == nil {
		return fmt.Errorf("tried to release not existing lock")
	}
	ctx := req.Context()
	return l.lock.Release(ctx)
}
