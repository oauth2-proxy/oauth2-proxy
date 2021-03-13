package sessions

import (
	"context"
	"time"
)

type NoOpLock struct{}

func (l *NoOpLock) Obtain(ctx context.Context, expiration time.Duration) error {
	return nil
}

func (l *NoOpLock) Peek(ctx context.Context) (bool, error) {
	return false, nil
}

func (l *NoOpLock) Refresh(ctx context.Context, expiration time.Duration) error {
	return nil
}

func (l *NoOpLock) Release(ctx context.Context) error {
	return nil
}
