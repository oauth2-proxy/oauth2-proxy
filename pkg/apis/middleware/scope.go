package middleware

import (
	"context"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type scopeKey string

// RequestScopeKey uses a typed string to reduce likelihood of clashing
// with other context keys
const RequestScopeKey scopeKey = "request-scope"

// RequestScope contains information regarding the request that is being made.
// The RequestScope is used to pass information between different middlewares
// within the chain.
type RequestScope struct {
	// ReverseProxy tracks whether OAuth2-Proxy is operating in reverse proxy
	// mode and if request `X-Forwarded-*` headers should be trusted
	ReverseProxy bool

	// RequestID is set to the request's `X-Request-Id` header if set.
	// Otherwise a random UUID is set.
	RequestID string

	// Session details the authenticated users information (if it exists).
	Session *sessions.SessionState

	// SaveSession indicates whether the session storage should attempt to save
	// the session or not.
	SaveSession bool

	// ClearSession indicates whether the user should be logged out or not.
	ClearSession bool

	// IntrospectToken indicates whether to introspect the session token.
	// This is set if the request has the header `X-Oauth2-Proxy-Introspect-Token`.
	IntrospectToken bool

	// SessionRevalidated indicates whether the session has been revalidated since
	// it was loaded or not.
	SessionRevalidated bool

	// Upstream tracks which upstream was used for this request
	Upstream string
}

// GetRequestScope returns the current request scope from the given request
func GetRequestScope(req *http.Request) *RequestScope {
	scope := req.Context().Value(RequestScopeKey)
	if scope == nil {
		return nil
	}

	return scope.(*RequestScope)
}

// AddRequestScope adds a RequestScope to a request
func AddRequestScope(req *http.Request, scope *RequestScope) *http.Request {
	ctx := context.WithValue(req.Context(), RequestScopeKey, scope)
	return req.WithContext(ctx)
}
