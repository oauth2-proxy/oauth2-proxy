package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

type responseWriter struct {
	http.ResponseWriter

	status int
	size   int
}

func NewResponseWriter(rw http.ResponseWriter) middlewareapi.ResponseWriter {
	return &responseWriter{
		ResponseWriter: rw,
	}
}

// Write writes the response using the ResponseWriter
func (r *responseWriter) Write(b []byte) (int, error) {
	if r.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		r.status = http.StatusOK
	}
	size, err := r.ResponseWriter.Write(b)
	r.size += size
	return size, err
}

// WriteHeader writes the status code for the Response
func (r *responseWriter) WriteHeader(s int) {
	r.ResponseWriter.WriteHeader(s)
	r.status = s
}

func (r *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("http.Hijacker is not available on writer")
}

// Flush sends any buffered data to the client
func (r *responseWriter) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		if r.status == 0 {
			// The status will be StatusOK if WriteHeader has not been called yet
			r.status = http.StatusOK
		}
		flusher.Flush()
	}
}

// Status returns the response status code
func (r *responseWriter) Status() int {
	return r.status
}

// Size returns the response size
func (r *responseWriter) Size() int {
	return r.size
}
