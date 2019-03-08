package middleware_test

import (
	"errors"
	"github.com/tumelohq/gke-ingress-healthcheck-middleware"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIngressHealthCheck(t *testing.T) {
	t.Parallel()
	tts := []struct {
		name       string
		ping       func() error
		handler    http.Handler
		path       string
		header     http.Header
		wantStatus int
		wantBody   string
	}{
		{
			name: "non health check request, root",
			ping: func() error { return nil },
			handler: func() http.Handler {
				h := http.NewServeMux()
				h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				})
				return h
			}(),
			path:       "/",
			wantStatus: http.StatusBadRequest,
			wantBody:   "",
		},
		{
			name: "non health check request, non root",
			ping: func() error { return nil },
			handler: func() http.Handler {
				h := http.NewServeMux()
				h.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				})
				return h
			}(),
			path:       "/test",
			wantStatus: http.StatusBadRequest,
			wantBody:   "",
		},
		{
			name: "health check, healthy",
			ping: func() error { return nil },
			handler: func() http.Handler {
				h := http.NewServeMux()
				h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				})
				return h
			}(),
			path: "/",
			header: func() http.Header {
				h := http.Header{}
				h.Set("User-Agent", "GoogleHC/1.0")
				return h
			}(),
			wantStatus: http.StatusOK,
			wantBody:   "",
		},
		{
			name: "health check, not healthy",
			ping: func() error { return errors.New("test") },
			handler: func() http.Handler {
				h := http.NewServeMux()
				h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				})
				return h
			}(),
			path: "/",
			header: func() http.Header {
				h := http.Header{}
				h.Set("User-Agent", "GoogleHC/1.0")
				return h
			}(),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// setup
			s := httptest.NewServer(middleware.IngressHealthCheck(tt.handler, tt.ping))
			defer s.Close()
			r, err := http.NewRequest(http.MethodGet, s.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header = tt.header

			// do
			res, err := s.Client().Do(r)
			if err != nil {
				t.Fatalf("get: %s", err)
			}

			// check
			if res.StatusCode != tt.wantStatus {
				t.Errorf("want status code %d, got %d", tt.wantStatus, res.StatusCode)
			}
			bodyBytes, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			b := string(bodyBytes)
			if b != "" {
				t.Error("non-empty body")
			}
		})
	}
}

func ExampleIngressHealthCheck() {
	// Handler
	h := http.NewServeMux()
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	// Sample ping Function
	ping := func() error {
		if rand.Int31n(100) > 50 {
			return errors.New("test error")
		}
		return nil
	}

	// Middleware
	wrapped := middleware.IngressHealthCheck(h, ping)

	// Serve
	log.Fatal(http.ListenAndServe("localhost:3030", wrapped))
}
