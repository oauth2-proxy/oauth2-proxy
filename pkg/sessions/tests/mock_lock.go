package tests

import (
	"context"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type MockLock struct {
	expireTime time.Time
}

func (l *MockLock) Obtain(ctx context.Context, expiration time.Duration) error {
	l.expireTime = time.Now().Add(expiration)
	return nil
}

func (l *MockLock) Peek(ctx context.Context) (bool, error) {
	if l.expireTime.After(time.Now()) {
		return true, nil
	}
	return false, nil
}

func (l *MockLock) Refresh(ctx context.Context, expiration time.Duration) error {
	if l.expireTime.Before(time.Now()) {
		return sessions.ErrNotLocked
	}
	l.expireTime = time.Now().Add(expiration)
	return nil
}

func (l *MockLock) Release(ctx context.Context) error {
	if l.expireTime.After(time.Now()) {
		return sessions.ErrNotLocked
	}
	l.expireTime = time.Now()
	return nil
}
