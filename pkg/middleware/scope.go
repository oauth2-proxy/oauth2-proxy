package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
)

func NewScope(reverseProxy bool, idHeader string, trustedProxies *ip.NetSet) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := &middlewareapi.RequestScope{
				ReverseProxy:   reverseProxy,
				TrustedProxies: trustedProxies,
				RequestID:      genRequestID(req, idHeader),
			}
			req = middlewareapi.AddRequestScope(req, scope)
			next.ServeHTTP(rw, req)
		})
	}
}

// genRequestID sets a request-wide ID for use in logging or error pages.
// If a RequestID header is set, it uses that. Otherwise, it generates a random
// UUID for the lifespan of the request.
func genRequestID(req *http.Request, idHeader string) string {
	rid := req.Header.Get(idHeader)
	if rid != "" {
		return rid
	}
	return uuid.New().String()
}
