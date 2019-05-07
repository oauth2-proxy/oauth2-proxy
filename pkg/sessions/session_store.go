package sessions

import (
	"fmt"

	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/sessions/cookie"
)

// NewSessionStore creates a SessionStore from the provided configuration
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	switch opts.Type {
	case options.CookieSessionStoreType:
		// Ensure EnableCipher is propogated from the parent option
		opts.CookieStoreOptions.EnableCipher = opts.EnableCipher
		return cookie.NewCookieSessionStore(opts.CookieStoreOptions, cookieOpts)
	default:
		return nil, fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}
