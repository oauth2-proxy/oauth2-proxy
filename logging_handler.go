// largely adapted from https://github.com/gorilla/handlers/blob/master/handlers.go
// to add logging of request duration as last value (and drop referrer)

package main

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
)

// responseLogger is wrapper of http.ResponseWriter that keeps track of its HTTP status
// code and body size
type responseLogger struct {
	w      http.ResponseWriter
	status int
	size   int
}

// Header returns the ResponseWriter's Header
func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

// Support Websocket
func (l *responseLogger) Hijack() (rwc net.Conn, buf *bufio.ReadWriter, err error) {
	if hj, ok := l.w.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("http.Hijacker is not available on writer")
}

// extractMetadata extracts metadata from the request/reqsponse for logging
func extractMetadata(rw http.ResponseWriter, req *http.Request) (string, string) {
	scope := middleware.GetRequestScope(req)
	upstream := scope.Upstream

	var authInfo string
	if scope.Session != nil {
		authInfo = scope.Session.Email
		if authInfo == "" {
			authInfo = scope.Session.User
		}
	}

	return authInfo, upstream
}

// Write writes the response using the ResponseWriter
func (l *responseLogger) Write(b []byte) (int, error) {
	if l.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		l.status = http.StatusOK
	}
	size, err := l.w.Write(b)
	l.size += size
	return size, err
}

// WriteHeader writes the status code for the Response
func (l *responseLogger) WriteHeader(s int) {
	l.w.WriteHeader(s)
	l.status = s
}

// Status returns the response status code
func (l *responseLogger) Status() int {
	return l.status
}

// Size returns the response size
func (l *responseLogger) Size() int {
	return l.size
}

// Flush sends any buffered data to the client
func (l *responseLogger) Flush() {
	if flusher, ok := l.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// loggingHandler is the http.Handler implementation for LoggingHandler
type loggingHandler struct {
	handler http.Handler
}

// LoggingHandler provides an http.Handler which logs requests to the HTTP server
func LoggingHandler(h http.Handler) http.Handler {
	return loggingHandler{
		handler: h,
	}
}

func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t := time.Now()
	url := *req.URL
	responseLogger := &responseLogger{w: w}
	h.handler.ServeHTTP(responseLogger, req)

	authInfo, upstream := extractMetadata(w, req)
	logger.PrintReq(authInfo, upstream, req, url, t, responseLogger.Status(), responseLogger.Size())
}
