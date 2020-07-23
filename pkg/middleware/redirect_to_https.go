package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/justinas/alice"
)

const httpsScheme = "https"

// NewRedirectToHTTPS creates a new redirectToHTTPS middleware that will redirect
// HTTP requests to HTTPS
func NewRedirectToHTTPS(httpsPort string) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return redirectToHTTPS(httpsPort, next)
	}
}

// redirectToHTTPS is an HTTP middleware the will redirect a request to HTTPS
// if it is not already HTTPS.
// If the request is to a non standard port, the redirection request will be
// to the port from the httpsAddress given.
func redirectToHTTPS(httpsPort string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		proto := req.Header.Get("X-Forwarded-Proto")
		if strings.EqualFold(proto, httpsScheme) || (req.TLS != nil && proto == "") {
			// Only care about the connection to us being HTTPS if the proto is empty,
			// otherwise the proto is source of truth
			next.ServeHTTP(rw, req)
			return
		}

		// Copy the request URL
		targetURL, _ := url.Parse(req.URL.String())
		// Set the scheme to HTTPS
		targetURL.Scheme = httpsScheme

		// Set the req.Host when the targetURL still does not have one
		if targetURL.Host == "" {
			targetURL.Host = req.Host
		}

		// Overwrite the port if the original request was to a non-standard port
		if targetURL.Port() != "" {
			// If Port was not empty, this should be fine to ignore the error
			host, _, _ := net.SplitHostPort(targetURL.Host)
			targetURL.Host = net.JoinHostPort(host, httpsPort)
		}

		http.Redirect(rw, req, targetURL.String(), http.StatusPermanentRedirect)
	})
}
