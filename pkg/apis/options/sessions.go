package options

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type         string `flag:"session-store-type" cfg:"session_store_type" env:"OAUTH2_PROXY_SESSION_STORE_TYPE"`
	EnableCipher bool   // Allow the user to choose encryption or not
	CookieStoreOptions
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	EnableCipher bool // Allow the user to choose encryption or not
}
