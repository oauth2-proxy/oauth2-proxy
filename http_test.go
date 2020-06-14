package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

func TestRedirectToHTTPSTrue(t *testing.T) {
	opts := options.NewOptions()
	opts.ForceHTTPS = true
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := redirectToHTTPS(opts, http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	h.ServeHTTP(rw, r)

	assert.Equal(t, http.StatusPermanentRedirect, rw.Code, "status code should be %d, got: %d", http.StatusPermanentRedirect, rw.Code)
}

func TestRedirectToHTTPSFalse(t *testing.T) {
	opts := options.NewOptions()
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := redirectToHTTPS(opts, http.HandlerFunc(handler))
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	h.ServeHTTP(rw, r)

	assert.Equal(t, http.StatusOK, rw.Code, "status code should be %d, got: %d", http.StatusOK, rw.Code)
}

func TestRedirectNotWhenHTTPS(t *testing.T) {
	opts := options.NewOptions()
	opts.ForceHTTPS = true
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("test"))
	}

	h := redirectToHTTPS(opts, http.HandlerFunc(handler))
	s := httptest.NewTLSServer(h)
	defer s.Close()

	opts.HTTPSAddress = s.URL
	client := s.Client()
	res, err := client.Get(s.URL)
	if err != nil {
		t.Fatalf("request to test server failed with error: %v", err)
	}

	assert.Equal(t, http.StatusOK, res.StatusCode, "status code should be %d, got: %d", http.StatusOK, res.StatusCode)
}

func TestGracefulShutdown(t *testing.T) {
	opts := options.NewOptions()
	stop := make(chan struct{}, 1)
	srv := Server{Handler: http.DefaultServeMux, Opts: opts, stop: stop}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.ServeHTTP()
	}()

	stop <- struct{}{} // emulate catching signals

	// An idiomatic for sync.WaitGroup with timeout
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
	case <-time.After(1 * time.Second):
		t.Fatal("Server should return gracefully but timeout has occurred")
	}

	assert.Len(t, stop, 0) // check if stop chan is empty
}
