package middleware

import (
	"context"
	"net/http"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

type scopeKey string

// requestScopeKey uses a typed string to reduce likelihood of clashing
// with other context keys
const requestScopeKey scopeKey = "request-scope"

func NewScope(opts *options.Options) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := &middlewareapi.RequestScope{
				ReverseProxy: opts.ReverseProxy,
			}
			contextWithScope := context.WithValue(req.Context(), requestScopeKey, scope)
			requestWithScope := req.WithContext(contextWithScope)
			next.ServeHTTP(rw, requestWithScope)
		})
	}
}

// GetRequestScope returns the current request scope from the given request
func GetRequestScope(req *http.Request) *middlewareapi.RequestScope {
	scope := req.Context().Value(requestScopeKey)
	if scope == nil {
		return nil
	}

	return scope.(*middlewareapi.RequestScope)
}
