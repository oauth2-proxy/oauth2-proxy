package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const localhost = "127.0.0.1"
const host = "test-server"

func TestGCPHealthcheckLiveness(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/liveness_check", nil)
	r.RemoteAddr = localhost
	r.Host = host
	h.ServeHTTP(rw, r)

	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "OK", rw.Body.String())
}

func TestGCPHealthcheckReadiness(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/readiness_check", nil)
	r.RemoteAddr = localhost
	r.Host = host
	h.ServeHTTP(rw, r)

	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "OK", rw.Body.String())
}

func TestGCPHealthcheckNotHealthcheck(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/not_any_check", nil)
	r.RemoteAddr = localhost
	r.Host = host
	h.ServeHTTP(rw, r)

	assert.Equal(t, "test", rw.Body.String())
}

func TestGCPHealthcheckIngress(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = localhost
	r.Host = host
	r.Header.Set(userAgentHeader, googleHealthCheckUserAgent)
	h.ServeHTTP(rw, r)

	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "", rw.Body.String())
}

func TestGCPHealthcheckNotIngress(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/foo", nil)
	r.RemoteAddr = localhost
	r.Host = host
	r.Header.Set(userAgentHeader, googleHealthCheckUserAgent)
	h.ServeHTTP(rw, r)

	assert.Equal(t, "test", rw.Body.String())
}

func TestGCPHealthcheckNotIngressPut(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("PUT", "/", nil)
	r.RemoteAddr = localhost
	r.Host = host
	r.Header.Set(userAgentHeader, googleHealthCheckUserAgent)
	h.ServeHTTP(rw, r)

	assert.Equal(t, "test", rw.Body.String())
}
