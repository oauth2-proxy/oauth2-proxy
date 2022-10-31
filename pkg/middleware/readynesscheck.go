package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/justinas/alice"
)

type Verifiable interface {
	VerifyConnection(context.Context) error
}

func NewReadynessCheck(path string, verifiable Verifiable) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return readynessCheck(path, verifiable, next)
	}
}

func readynessCheck(path string, verifiable Verifiable, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if path != "" && req.URL.EscapedPath() == path {
			if err := verifiable.VerifyConnection(req.Context()); err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(rw, "error: %v", err)
				return
			}
			rw.WriteHeader(http.StatusOK)
			fmt.Fprintf(rw, "OK")
			return
		}

		next.ServeHTTP(rw, req)
	})
}
