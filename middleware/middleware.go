package middleware

import (
	"net/http"
)

const userAgentHeader = "User-Agent"
const googleHealthCheckUserAgent = "GoogleHC/1.0"
const rootPath = "/"

// IngressHealthCheck is a middleware that is designed to be used with the Ingress in GKE. The ingress requires the root
// path of the target to return a 200 (OK) to indicate the service's good health. This can be quite a challenging demand
// depending on the application's path structure. This middleware filters out the requests from the health check by
//
// 1. checking that the request path is indeed the root path
// 2. ensuring that the User-Agent is "GoogleHC/1.0", the health checker
// 3. ensuring the request method is "GET"
//
// The ping can be used to indicate the health of the service. Like the sql package implementation, if it returns an
// error, the middleware will return a unhealthy response by returning a 500 (Internal). Otherwise if healthy, it
// returns a 200 (OK).
//
// An error that causes an "unhealthy" is not returned to the health check for security purposes.
func IngressHealthCheck(next http.Handler, ping func() error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == rootPath &&
			r.Header.Get(userAgentHeader) == googleHealthCheckUserAgent &&
			r.Method == http.MethodGet {
			if err := ping(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
