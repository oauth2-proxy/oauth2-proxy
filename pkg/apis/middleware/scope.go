package middleware

import (
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// RequestScope contains information regarding the request that is being made.
// The RequestScope is used to pass information between different middlewares
// within the chain.
type RequestScope struct {
	// Session details the authenticated users information (if it exists).
	Session *sessions.SessionState

	// SaveSession indicates whether the session storage should attempt to save
	// the session or not.
	SaveSession bool

	// ClearSession indicates whether the user should be logged out or not.
	ClearSession bool

	// SessionRevalidated indicates whether the session has been revalidated since
	// it was loaded or not.
	SessionRevalidated bool
}
