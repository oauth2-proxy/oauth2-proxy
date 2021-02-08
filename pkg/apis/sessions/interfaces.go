package sessions

import (
	"net/http"
	"time"
)

// SessionStore is an interface to storing user sessions in the proxy
type SessionStore interface {
	Save(rw http.ResponseWriter, req *http.Request, s *SessionState) error
	Load(req *http.Request) (*SessionState, error)
	Lock(req *http.Request, expiration time.Duration) error
	Clear(rw http.ResponseWriter, req *http.Request) error
}
