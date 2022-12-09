package middleware

import (
	"net/http"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/types"
)

// middleware that loads tenant from the http request and then stores it in the context
func NewTenantLoader(loader types.Loader) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			tnt, err := loader.Load(req)
			if err != nil {
				logger.Error(err)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx := tenant.AppendToContext(req.Context(), tnt)
			next.ServeHTTP(rw, req.WithContext(ctx))
		})
	}
}
