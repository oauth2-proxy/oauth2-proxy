package upstream

import (
	"fmt"
	"net/http"
)

const defaultStaticResponseCode = 200

// newStaticResponseHandler creates a new staticResponseHandler that serves a
// a static response code.
func newStaticResponseHandler(upstream string, code *int) http.Handler {
	return &staticResponseHandler{
		code:     derefStaticCode(code),
		upstream: upstream,
	}
}

// staticResponseHandler responds with a static response with the given response code.
type staticResponseHandler struct {
	code     int
	upstream string
}

// ServeHTTP serves a static response.
func (s *staticResponseHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("GAP-Upstream-Address", s.upstream)
	rw.WriteHeader(s.code)
	fmt.Fprintf(rw, "Authenticated")
}

// derefStaticCode returns the derefenced value, or the default if the value is nil
func derefStaticCode(code *int) int {
	if code != nil {
		return *code
	}
	return defaultStaticResponseCode
}
