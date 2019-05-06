package cookie

import (
	"fmt"
	"net/http"

	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
)

// Ensure CookieSessionStore implements the interface
var _ sessions.SessionStore = &SessionStore{}

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in client side cookies
type SessionStore struct{}

// SaveSession takes a sessions.SessionState and stores the information from it
// within Cookies set on the HTTP response writer
func (c *SessionStore) SaveSession(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	return fmt.Errorf("method not implemented")
}

// LoadSession reads sessions.SessionState information from Cookies within the
// HTTP request object
func (c *SessionStore) LoadSession(req *http.Request) (*sessions.SessionState, error) {
	return nil, fmt.Errorf("method not implemented")
}

// ClearSession clears any saved session information by writing a cookie to
// clear the session
func (c *SessionStore) ClearSession(rw http.ResponseWriter, req *http.Request) error {
	return fmt.Errorf("method not implemented")
}

// NewCookieSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewCookieSessionStore(opts options.CookieStoreOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	return &SessionStore{}, fmt.Errorf("method not implemented")
}
