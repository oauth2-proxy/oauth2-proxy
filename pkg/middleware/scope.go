package middleware

import (
	"context"
	"net/http"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/middleware"
)

type scopeKey string

// requestScopeKey uses a typed string to reduce likelihood of clasing
// with other context keys
const requestScopeKey scopeKey = "request-scope"

func NewScope() alice.Constructor {
	return addScope
}

// addScope injects a new request scope into the request context.
func addScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := &middlewareapi.RequestScope{}
		contextWithScope := context.WithValue(req.Context(), requestScopeKey, scope)
		requestWithScope := req.WithContext(contextWithScope)
		next.ServeHTTP(rw, requestWithScope)
	})
}

// GetRequestScope returns the current request scope from the given request
func GetRequestScope(req *http.Request) *middlewareapi.RequestScope {
	scope := req.Context().Value(requestScopeKey)
	if scope == nil {
		return nil
	}

	return scope.(*middlewareapi.RequestScope)
}
