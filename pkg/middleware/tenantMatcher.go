package middleware

import (
	"net/http"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenantmatcher"
)

// middleware that extracts tenantId from the http request and then stores it in the context
func NewTenantMatcher(tenantMatcher *tenantmatcher.Matcher) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

			tenantId := tenantMatcher.Match(req)

			ctx := tenantmatcher.AppendToContext(req.Context(), tenantId)
			next.ServeHTTP(rw, req.WithContext(ctx))
		})
	}
}
