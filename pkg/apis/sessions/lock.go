package sessions

import (
	"context"
	"time"
)

type NoOpLock struct{}

func (l *NoOpLock) Obtain(_ context.Context, _ time.Duration) error {
	return nil
}

func (l *NoOpLock) Peek(_ context.Context) (bool, error) {
	return false, nil
}

func (l *NoOpLock) Refresh(_ context.Context, _ time.Duration) error {
	return nil
}

func (l *NoOpLock) Release(_ context.Context) error {
	return nil
}
