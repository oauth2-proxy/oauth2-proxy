package upstream

import (
	"net/http"

	"github.com/mbland/hmacauth"
)

// StripPrefix returns a handler that serves HTTP requests by adding
// a signature to the request header set and invoking the handler h.
func SignRequest(signer hmacauth.HmacAuth, h http.Handler) http.Handler {
	if signer == nil {
		return h
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("GAP-Auth", w.Header().Get("GAP-Auth"))
		signer.SignRequest(r)

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(handler)
}
