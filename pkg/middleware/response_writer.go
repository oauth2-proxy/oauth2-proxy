package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"reflect"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

type responseWriter struct {
	http.ResponseWriter

	middlewareapi.ResponseTimer
	middlewareapi.ResponseMetadata

	status int
	size   int
}

func NewResponseWriter(rw http.ResponseWriter) middlewareapi.ResponseWriter {
	return &responseWriter{
		ResponseWriter:   rw,
		ResponseTimer:    &timer{},
		ResponseMetadata: &metadata{},
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

type timer struct {
	start *time.Time
}

func (t *timer) Start() {
	now := time.Now()
	t.start = &now
}

func (t *timer) Duration() (time.Duration, error) {
	if t.start == nil {
		return time.Second * 0, errors.New("timer not started")
	}
	return time.Since(*t.start), nil
}

type metadata struct {
	data map[interface{}]interface{}
}

func (m metadata) SetMetadata(key interface{}, value interface{}) {
	if key == nil {
		panic("nil key")
	}
	if !reflect.TypeOf(key).Comparable() {
		panic("key is not comparable")
	}

	if m.data == nil {
		m.data = make(map[interface{}]interface{})
	}
	m.data[key] = value
}

func (m metadata) GetMetadata(key interface{}) interface{} {
	if val, ok := m.data[key]; ok {
		return val
	}
	return nil
}
