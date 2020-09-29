package main

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

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
