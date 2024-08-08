package middleware

import (
	"net/http"

	middlewareapi "github.com/Jing-ze/oauth2-proxy/pkg/apis/middleware"

	"github.com/google/uuid"
	"github.com/justinas/alice"
)

func NewScope(reverseProxy bool, idHeader string) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := &middlewareapi.RequestScope{
				ReverseProxy: reverseProxy,
				RequestID:    genRequestID(req, idHeader),
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
