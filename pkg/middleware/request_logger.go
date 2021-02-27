package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// NewRequestLogger returns middleware which logs requests
// It uses a custom ResponseWriter to track status code & response size details
func NewRequestLogger() alice.Constructor {
	return requestLogger
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		startTime := time.Now()
		url := *req.URL

		responseLogger := &loggingResponse{ResponseWriter: rw}
		next.ServeHTTP(responseLogger, req)

		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		logger.PrintReq(
			getUser(scope),
			scope.Upstream,
			req,
			url,
			startTime,
			responseLogger.Status(),
			responseLogger.Size(),
		)
	})
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

// loggingResponse is a custom http.ResponseWriter that allows tracking certain
// details for request logging.
type loggingResponse struct {
	http.ResponseWriter

	status int
	size   int
}

// Write writes the response using the ResponseWriter
func (r *loggingResponse) Write(b []byte) (int, error) {
	if r.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		r.status = http.StatusOK
	}
	size, err := r.ResponseWriter.Write(b)
	r.size += size
	return size, err
}

// WriteHeader writes the status code for the Response
func (r *loggingResponse) WriteHeader(s int) {
	r.ResponseWriter.WriteHeader(s)
	r.status = s
}

// Hijack implements the `http.Hijacker` interface that actual ResponseWriters
// implement to support websockets
func (r *loggingResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("http.Hijacker is not available on writer")
}

// Flush sends any buffered data to the client. Implements the `http.Flusher`
// interface
func (r *loggingResponse) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		if r.status == 0 {
			// The status will be StatusOK if WriteHeader has not been called yet
			r.status = http.StatusOK
		}
		flusher.Flush()
	}
}

// Status returns the response status code
func (r *loggingResponse) Status() int {
	return r.status
}

// Size returns the response size
func (r *loggingResponse) Size() int {
	return r.size
}
