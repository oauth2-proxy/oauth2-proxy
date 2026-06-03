package sessions

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// SessionStore is an interface to storing user sessions in the proxy
type SessionStore interface {
	Save(rw http.ResponseWriter, req *http.Request, s *SessionState) error
	Load(req *http.Request) (*SessionState, error)
	Clear(rw http.ResponseWriter, req *http.Request) error
	VerifyConnection(ctx context.Context) error
}

// BackChannelSessionStore extends SessionStore with support for
// OIDC back-channel logout (https://openid.net/specs/openid-connect-backchannel-1_0.html).
// Persistent stores (e.g. Redis) implement this to enable instant logout
// when the provider sends a back-channel logout request.
type BackChannelSessionStore interface {
	SessionStore
	// ClearBySID removes the session associated with the given OIDC session ID (sid claim).
	ClearBySID(ctx context.Context, sessionID string) error
}

var ErrLockNotObtained = errors.New("lock: not obtained")
var ErrNotLocked = errors.New("tried to release not existing lock")

// Lock is an interface for controlling session locks
type Lock interface {
	// Obtain obtains the lock on the distributed
	// lock resource if no lock exists yet.
	// Otherwise it will return ErrLockNotObtained
	Obtain(ctx context.Context, expiration time.Duration) error
	// Peek returns true if the lock currently exists
	// Otherwise it returns false.
	Peek(ctx context.Context) (bool, error)
	// Refresh refreshes the expiration time of the lock,
	// if is still applied.
	// Otherwise it will return ErrNotLocked
	Refresh(ctx context.Context, expiration time.Duration) error
	// Release removes the existing lock,
	// Otherwise it will return ErrNotLocked
	Release(ctx context.Context) error
}
