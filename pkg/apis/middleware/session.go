package middleware

import (
	"context"

	"github.com/coreos/go-oidc"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// TokenToSessionFunc takes a rawIDToken and an idToken and converts it into a
// SessionState.
type TokenToSessionFunc func(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessionsapi.SessionState, error)

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
