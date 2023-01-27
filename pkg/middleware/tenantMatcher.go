package middleware

import (
	"net/http"

	"github.com/justinas/alice"
	tenantmatcher "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/matcher"
	tenantutils "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/utils"
)

// middleware that extracts tenantId from the http request and then stores it in the context
func NewTenantMatcher(tenantMatcher *tenantmatcher.Matcher) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

			tenantId := tenantMatcher.Match(req)

			ctx := tenantutils.AppendToContext(req.Context(), tenantId)
			next.ServeHTTP(rw, req.WithContext(ctx))
		})
	}
}
