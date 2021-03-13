package sessions

import (
	"net/http"
	"time"
)

type NoOpLock struct{}

func (l *NoOpLock) Obtain(req *http.Request, expiration time.Duration) error {
	return nil
}

func (l *NoOpLock) Peek(req *http.Request) (bool, error) {
	return false, nil
}

func (l *NoOpLock) Refresh(req *http.Request, expiration time.Duration) error {
	return nil
}

func (l *NoOpLock) Release(req *http.Request) error {
	return nil
}
