package sessions

import (
	"net/http"
)

// SessionStore is an interface to storing user sessions in the proxy
type SessionStore interface {
	SaveSession(rw http.ResponseWriter, req *http.Request, s *SessionState) error
	LoadSession(req *http.Request) (*SessionState, error)
	ClearSession(rw http.ResponseWriter, req *http.Request) error
}
