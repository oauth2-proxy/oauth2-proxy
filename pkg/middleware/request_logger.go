package middleware

import (
	"github.com/justinas/alice"
	"net/http"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

type (
	upstreamKey string
	userKey     string
)

const (
	loggerUpstreamKey upstreamKey = "logger-upstream"
	loggerUserKey     userKey     = "logger-user"
)

func NewRequestLogger() alice.Constructor {
	return requestLogger
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		url := *req.URL

		next.ServeHTTP(rw, req)

		if mrw, ok := rw.(middlewareapi.ResponseWriter); ok {
			duration, err := mrw.Duration()
			if err != nil {
				logger.Errorf("Error timing the request: %v", err)
				duration = time.Second * 0
			}

			logger.PrintReq(
				getUser(mrw),
				getUpstream(mrw),
				req,
				url,
				duration,
				mrw.Status(),
				mrw.Size(),
			)
			return
		}

		logger.PrintReq("", "", req, url, time.Second*0, 0, 0)
	})
}

func LogUpstream(rm middlewareapi.ResponseMetadata, upstream string) {
	rm.SetMetadata(loggerUpstreamKey, upstream)
}

func LogUser(rm middlewareapi.ResponseMetadata, upstream string) {
	rm.SetMetadata(loggerUpstreamKey, upstream)
}

func getUpstream(rm middlewareapi.ResponseMetadata) string {
	if upstream, ok := rm.GetMetadata(loggerUpstreamKey).(string); ok {
		return upstream
	}
	return ""
}

func getUser(rm middlewareapi.ResponseMetadata) string {
	if user, ok := rm.GetMetadata(loggerUserKey).(string); ok {
		return user
	}
	return ""
}
