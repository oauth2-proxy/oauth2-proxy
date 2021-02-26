package sessions

import (
	"github.com/pkg/errors"
	"net/http"
)

var ErrNotLockable = errors.New("not able to lock session state")

// SessionStore is an interface to storing user sessions in the proxy
type SessionStore interface {
	Save(rw http.ResponseWriter, req *http.Request, s *SessionState) error
	Load(req *http.Request) (*SessionState, error)
	LoadWithLock(req *http.Request) (*SessionState, error)
	ReleaseLock(req *http.Request) error
	Clear(rw http.ResponseWriter, req *http.Request) error
}
