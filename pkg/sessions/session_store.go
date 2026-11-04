package sessions

import (
	"fmt"
	"io"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/sqlite"
)

// NewSessionStore creates a SessionStore from the provided configuration
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	switch opts.Type {
	case options.CookieSessionStoreType:
		return cookie.NewCookieSessionStore(opts, cookieOpts)
	case options.RedisSessionStoreType:
		return redis.NewRedisSessionStore(opts, cookieOpts)
	case options.SQLiteSessionStoreType:
		return sqlite.NewSQLiteSessionStore(opts, cookieOpts)
	default:
		return nil, fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}

// CloseSessionStore closes the store if it implements io.Closer.
func CloseSessionStore(store sessions.SessionStore) {
	if closer, ok := store.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			logger.Errorf("Error closing session store: %v", err)
		}
	}
}
