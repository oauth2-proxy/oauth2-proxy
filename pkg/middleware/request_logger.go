package middleware

import (
	"net/http"
	"time"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

func NewRequestLogger() alice.Constructor {
	return requestLogger
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		url := *req.URL

		next.ServeHTTP(rw, req)

		scope := getScope(req)
		logger.PrintReq(
			getUser(scope),
			scope.Upstream,
			req,
			url,
			startTime,
			rw.(middlewareapi.ResponseWriter).Status(),
			rw.(middlewareapi.ResponseWriter).Size(),
		)
	})
}

func getScope(req *http.Request) *middlewareapi.RequestScope {
	scope := middlewareapi.GetRequestScope(req)
	if scope != nil {
		return scope
	}
	return &middlewareapi.RequestScope{}
}

func getUser(scope *middlewareapi.RequestScope) string {
	session := scope.Session
	if session != nil {
		if session.Email != "" {
			return session.Email
		}
		return session.User
	}
	return ""
}
