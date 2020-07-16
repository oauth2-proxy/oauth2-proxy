package conditions

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// Condition is the underlying building block of a Rule
type Condition interface {
	// Match returns a bool based on details of the Request or Session
	Match(*http.Request, *sessions.SessionState) bool
}
