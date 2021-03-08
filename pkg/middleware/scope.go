package middleware

import (
	"net/http"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

func NewScope(reverseProxy bool) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := &middlewareapi.RequestScope{
				ReverseProxy: reverseProxy,
				RequestID:    requestutil.GetRequestID(req),
			}
			req = middlewareapi.AddRequestScope(req, scope)
			next.ServeHTTP(rw, req)
		})
	}
}
