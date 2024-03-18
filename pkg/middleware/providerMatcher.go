package middleware

import (
	"net/http"

	"github.com/justinas/alice"
	providermatcher "github.com/oauth2-proxy/oauth2-proxy/v7/providers/matcher"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

// middleware that extracts providerId from the http request and then stores it in the context
func NewProviderMatcher(providerMatcher *providermatcher.Matcher) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

			providerID := providerMatcher.Match(req)

			ctx := utils.AppendToContext(req.Context(), providerID)
			next.ServeHTTP(rw, req.WithContext(ctx))
		})
	}
}
