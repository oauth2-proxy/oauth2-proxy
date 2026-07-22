package http

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
)

// NewHTTPSessionStore initialises a new instance of the HTTP Store and wraps
// it in a persistence.Manager
func NewHTTPSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	if opts.HTTP.BaseURL == "" {
		return nil, fmt.Errorf("http-store-base-url must be set when using http session store")
	}

	store, err := NewStore(opts.HTTP.BaseURL, opts.HTTP.APIKey)
	if err != nil {
		return nil, fmt.Errorf("error constructing http store: %v", err)
	}

	return persistence.NewManager(store, cookieOpts), nil
}
