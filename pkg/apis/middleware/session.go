package middleware

import (
	"context"
	"time"

	"github.com/coreos/go-oidc"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// ProxyState is not serializable and carries proxy-scoped values and settings.
// It can, hypothetically, change between the provider calls
type ProxyState struct {
	// Session storage backend
	SessionStore sessionsapi.SessionStore

	// The time period when cookie should expire
	CookieExpire time.Duration

	// How often should sessions be refreshed
	CookieRefreshPeriod time.Duration

	// How soon before the contents expiration should the session be refreshed
	CookieRefreshGracePcnt uint8
}

// TokenToSessionFunc takes a rawIDToken and an idToken and converts it into a
// SessionState.
type TokenToSessionFunc func(ctx context.Context, ps ProxyState, rawIDToken string, idToken *oidc.IDToken) (*sessionsapi.SessionState, error)

// TokenToSessionLoader pairs a token verifier with the correct converter function
// to convert the ID Token to a SessionState.
type TokenToSessionLoader struct {
	// Verfier is used to verify that the ID Token was signed by the claimed issuer
	// and that the token has not been tampered with.
	Verifier *oidc.IDTokenVerifier

	// TokenToSession converts a rawIDToken and an idToken to a SessionState.
	// (Optional) If not set a default basic implementation is used.
	TokenToSession TokenToSessionFunc
}
