// largely adapted from https://github.com/gorilla/handlers/blob/master/handlers.go
// to add logging of request duration as last value (and drop referrer)

package main

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	zap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

// Header returns the ResponseWriter's Header
func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

// ExtractGAPMetadata extracts and removes GAP headers from the ResponseWriter's
// Header
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

// Write writes the response using the ResponseWriter
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

// WriteHeader writes the status code for the Response
func (l *responseLogger) WriteHeader(s int) {
	l.ExtractGAPMetadata()
	l.w.WriteHeader(s)
	l.status = s
}

// Status returns the response status code
func (l *responseLogger) Status() int {
	return l.status
}

// Size returns teh response size
func (l *responseLogger) Size() int {
	return l.size
}

func (l *responseLogger) Flush() {
	if flusher, ok := l.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// loggingHandler is the http.Handler implementation for LoggingHandlerTo and its friends
type loggingHandler struct {
	logger  *zap.Logger
	writer  io.Writer
	handler http.Handler
	enabled bool
}

// LoggingHandler provides an http.Handler which logs requests to the HTTP server
func LoggingHandler(h http.Handler, v bool, logPath string) http.Handler {
	var logger *zap.Logger
	if v {
		config := zap.NewProductionConfig()
		config.OutputPaths = []string{logPath}
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		logger, _ = config.Build()
	} else {
		logger = zap.NewNop()
	}
	defer logger.Sync()
	return loggingHandler{
		logger:  logger,
		handler: h,
		enabled: v,
	}
}

func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t := time.Now()
	url := *req.URL
	logger := &responseLogger{w: w}
	h.handler.ServeHTTP(logger, req)
	if !h.enabled {
		return
	}
	h.writeLogLine(logger.authInfo, logger.upstream, req, url, t, logger.Status(), logger.Size())
}

// Log entry for req similar to Apache Common Log Format.
// ts is the timestamp with which the entry should be logged.
// status, size are used to provide the response HTTP status and size.
func (h loggingHandler) writeLogLine(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) {
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

	duration := time.Now().Sub(ts)

	h.logger.Info("HTTP Request",
		zap.String("Client", client),
		zap.String("Host", req.Host),
		zap.String("Protocol", req.Proto),
		zap.Duration("RequestDuration", duration),
		zap.String("RequestMethod", req.Method),
		zap.String("RequestURI", url.RequestURI()),
		zap.Int("ResponseSize", size),
		zap.Int("StatusCode", status),
		zap.Time("Timestamp", ts),
		zap.String("Upstream", upstream),
		zap.String("UserAgent", req.UserAgent()),
		zap.String("Username", username),
	)
}
