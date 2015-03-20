// largely adapted from https://github.com/gorilla/handlers/blob/master/handlers.go
// to add logging of request duration as last value (and drop referrer)

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// responseLogger is wrapper of http.ResponseWriter that keeps track of its HTTP status
// code and body size
type responseLogger struct {
	w        http.ResponseWriter
	status   int
	size     int
	upstream string
	authInfo string
}

func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

func (l *responseLogger) ExtractGAPMetadata() {
	upstream := l.w.Header().Get("GAP-Upstream-Address")
	if upstream != "" {
		l.upstream = upstream
		l.w.Header().Del("GAP-Upstream-Address")
	}
	authInfo := l.w.Header().Get("GAP-Auth")
	if authInfo != "" {
		l.authInfo = authInfo
		l.w.Header().Del("GAP-Auth")
	}
}

func (l *responseLogger) Write(b []byte) (int, error) {
	if l.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		l.status = http.StatusOK
	}
	l.ExtractGAPMetadata()
	size, err := l.w.Write(b)
	l.size += size
	return size, err
}

func (l *responseLogger) WriteHeader(s int) {
	l.ExtractGAPMetadata()
	l.w.WriteHeader(s)
	l.status = s
}

func (l *responseLogger) Status() int {
	return l.status
}

func (l *responseLogger) Size() int {
	return l.size
}

// loggingHandler is the http.Handler implementation for LoggingHandlerTo and its friends
type loggingHandler struct {
	writer  io.Writer
	handler http.Handler
	enabled bool
}

func LoggingHandler(out io.Writer, h http.Handler, v bool) http.Handler {
	return loggingHandler{out, h, v}
}

func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t := time.Now()
	url := *req.URL
	logger := &responseLogger{w: w}
	h.handler.ServeHTTP(logger, req)
	if !h.enabled {
		return
	}
	logLine := buildLogLine(logger.authInfo, logger.upstream, req, url, t, logger.Status(), logger.Size())
	h.writer.Write(logLine)
}

// Log entry for req similar to Apache Common Log Format.
// ts is the timestamp with which the entry should be logged.
// status, size are used to provide the response HTTP status and size.
func buildLogLine(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) []byte {
	if username == "" {
		username = "-"
	}
	if upstream == "" {
		upstream = "-"
	}
	if url.User != nil && username == "-" {
		if name := url.User.Username(); name != "" {
			username = name
		}
	}

	client := req.Header.Get("X-Real-IP")
	if client == "" {
		client = req.RemoteAddr
	}

	if c, _, err := net.SplitHostPort(client); err == nil {
		client = c
	}

	duration := float64(time.Now().Sub(ts)) / float64(time.Second)

	logLine := fmt.Sprintf("%s - %s [%s] %s %s %s %q %s %q %d %d %0.3f\n",
		client,
		username,
		ts.Format("02/Jan/2006:15:04:05 -0700"),
		req.Host,
		req.Method,
		upstream,
		url.RequestURI(),
		req.Proto,
		req.UserAgent(),
		status,
		size,
		duration,
	)
	return []byte(logLine)
}
