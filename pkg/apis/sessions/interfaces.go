package sessions

import (
	"context"
	"net/http"
	"time"
)

// SessionStore is an interface to storing user sessions in the proxy
type SessionStore interface {
	Save(rw http.ResponseWriter, req *http.Request, s *SessionState) error
	Load(req *http.Request) (*SessionState, error)
	Clear(rw http.ResponseWriter, req *http.Request) error
}

type Lock interface {
	Obtain(ctx context.Context, expiration time.Duration) error
	Peek(ctx context.Context) (bool, error)
	Refresh(ctx context.Context, expiration time.Duration) error
	Release(ctx context.Context) error
}
