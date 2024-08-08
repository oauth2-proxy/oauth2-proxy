package sessions

import (
	"fmt"

	"github.com/higress-group/oauth2-proxy/pkg/apis/options"
	"github.com/higress-group/oauth2-proxy/pkg/apis/sessions"
	"github.com/higress-group/oauth2-proxy/pkg/sessions/cookie"
)

// NewSessionStore creates a SessionStore from the provided configuration
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	switch opts.Type {
	case options.CookieSessionStoreType:
		return cookie.NewCookieSessionStore(opts, cookieOpts)
	default:
		return nil, fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}
