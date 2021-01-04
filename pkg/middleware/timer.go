package middleware

import (
	"github.com/justinas/alice"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

// NewTimer times the duration of the middleware lifecycle
func NewTimer() alice.Constructor {
	return startTimer
}

// startTimer starts the ResponseTimer
func startTimer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if timer, ok := rw.(middlewareapi.ResponseTimer); ok {
			timer.Start()
		}
		next.ServeHTTP(rw, req)
	})
}
