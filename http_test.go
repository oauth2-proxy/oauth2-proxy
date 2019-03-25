package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCPHealthcheckLiveness(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/liveness_check", nil)
	r.RemoteAddr = "127.0.0.1"
	r.Host = "test-server"
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
	r.RemoteAddr = "127.0.0.1"
	r.Host = "test-server"
	h.ServeHTTP(rw, r)

	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "OK", rw.Body.String())
}

func TestGCPHealthcheckNotReadiness(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/NOT_readiness_check", nil)
	r.RemoteAddr = "127.0.0.1"
	r.Host = "test-server"
	h.ServeHTTP(rw, r)

	assert.NotEqual(t, "OK", rw.Body.String())
}

func TestGCPHealthcheckNotLiveness(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := gcpHealthcheck(http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/NOT_liveness_check", nil)
	r.RemoteAddr = "127.0.0.1"
	r.Host = "test-server"
	h.ServeHTTP(rw, r)

	assert.NotEqual(t, "OK", rw.Body.String())
}
