package sessions

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/redis"
)

// NewSessionStore creates a SessionStore from the provided configuration
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	cipher, err := encryption.NewBase64Cipher(encryption.NewCFBCipher, encryption.SecretBytes(cookieOpts.Secret))
	if err != nil {
		return nil, fmt.Errorf("error initialising cipher: %v", err)
	}
	switch opts.Type {
	case options.CookieSessionStoreType:
		return cookie.NewCookieSessionStore(opts, cookieOpts, cipher)
	case options.RedisSessionStoreType:
		return redis.NewRedisSessionStore(opts, cookieOpts, cipher)
	default:
		return nil, fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}
