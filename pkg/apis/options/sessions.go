package options

import (
	"github.com/pusher/oauth2_proxy/cookie"
)

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type   string `flag:"session-store-type" cfg:"session_store_type" env:"OAUTH2_PROXY_SESSION_STORE_TYPE"`
	Cipher *cookie.Cipher
	CookieStoreOptions
	RedisStoreOptions
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct{}

// RedisSessionStoreType is used to indicate the RedisSessionStore should be
// used for storing sessions.
var RedisSessionStoreType = "redis"

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	RedisConnectionURL string `flag:"redis-connection-url" cfg:"redis_connection_url" env:"OAUTH2_PROXY_REDIS_CONNECTION_URL"`
}
