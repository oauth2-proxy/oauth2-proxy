package tests

import (
	"context"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type MockLock struct {
	expiration time.Duration
	elapsed    time.Duration
}

func (l *MockLock) Obtain(_ context.Context, expiration time.Duration) error {
	l.expiration = expiration
	return nil
}

func (l *MockLock) Peek(_ context.Context) (bool, error) {
	if l.elapsed < l.expiration {
		return true, nil
	}
	return false, nil
}

func (l *MockLock) Refresh(_ context.Context, expiration time.Duration) error {
	if l.expiration <= l.elapsed {
		return sessions.ErrNotLocked
	}
	l.expiration = expiration
	l.elapsed = time.Duration(0)
	return nil
}

func (l *MockLock) Release(_ context.Context) error {
	if l.expiration <= l.elapsed {
		return sessions.ErrNotLocked
	}
	l.expiration = time.Duration(0)
	l.elapsed = time.Duration(0)
	return nil
}

// FastForward simulates the flow of time to test expirations
func (l *MockLock) FastForward(duration time.Duration) {
	l.elapsed += duration
}
