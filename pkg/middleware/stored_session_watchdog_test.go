package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type countingLock struct {
	mu        sync.Mutex
	locked    bool
	refreshes int
}

func (l *countingLock) Obtain(context.Context, time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locked = true
	return nil
}

func (l *countingLock) Peek(context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.locked, nil
}

func (l *countingLock) Refresh(context.Context, time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refreshes++
	return nil
}

func (l *countingLock) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locked = false
	return nil
}

func (l *countingLock) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refreshes
}

func TestRefreshLockLeaseIsRenewedDuringSlowRedeem(t *testing.T) {
	lock := &countingLock{}
	createdPast := time.Now().Add(-5 * time.Minute)
	session := &sessionsapi.SessionState{RefreshToken: "Refresh", CreatedAt: &createdPast, Lock: lock}

	store := &fakeSessionStore{
		LoadFunc: func(*http.Request) (*sessionsapi.SessionState, error) {
			fresh := *session
			fresh.Lock = &testLock{}
			return &fresh, nil
		},
		SaveFunc: func(http.ResponseWriter, *http.Request, *sessionsapi.SessionState) error { return nil },
	}

	s := &storedSessionLoader{
		refreshPeriod: time.Minute,
		store:         store,
		sessionRefresher: func(context.Context, *sessionsapi.SessionState) (bool, error) {
			time.Sleep(sessionRefreshLockDuration) // redeem slower than the un-renewed lock TTL
			return true, nil
		},
		sessionValidator: func(context.Context, *sessionsapi.SessionState) bool { return true },
	}

	if err := s.refreshSessionIfNeeded(nil, httptest.NewRequest("", "/", nil), session); err != nil {
		t.Fatalf("refreshSessionIfNeeded returned error: %v", err)
	}
	if got := lock.count(); got < 1 {
		t.Fatalf("expected the lock lease to be renewed at least once during a slow redeem, got %d", got)
	}
}
