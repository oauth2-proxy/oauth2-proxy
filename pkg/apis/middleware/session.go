package middleware

import (
	"context"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// TokenToSessionFunc takes a rawIDToken and an idToken and converts it into a
// SessionState.
type TokenToSessionFunc func(ctx context.Context, token string, verify VerifyFunc) (*sessionsapi.SessionState, error)

// VerifyFunc takes a raw bearer token and verifies it
type VerifyFunc func(ctx context.Context, token string) (interface{}, error)

// TokenToSessionLoader pairs a token verifier with the correct converter function
// to convert the ID Token to a SessionState.
type TokenToSessionLoader struct {
	// Verifier is used to verify that the ID Token was signed by the claimed issuer
	// and that the token has not been tampered with.
	Verifier VerifyFunc

	// TokenToSession converts a raw bearer token to a SessionState.
	// (Optional) If not set a default basic implementation is used.
	TokenToSession TokenToSessionFunc
}
