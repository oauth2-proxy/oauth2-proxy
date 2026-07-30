package util

import (
	"net/http"
	"net/url"
	"strings"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

const (
	XForwardedProto = "X-Forwarded-Proto"
	XForwardedHost  = "X-Forwarded-Host"
	XForwardedURI   = "X-Forwarded-Uri"
)

// GetRequestProto returns the request scheme or X-Forwarded-Proto if present
// and the request came from a trusted reverse proxy.
func GetRequestProto(req *http.Request) string {
	proto := req.Header.Get(XForwardedProto)
	if !CanTrustForwardedHeaders(req) || proto == "" {
		proto = req.URL.Scheme
	}
	return proto
}

// GetRequestHost returns the request host header or X-Forwarded-Host if
// present and the request came from a trusted reverse proxy.
func GetRequestHost(req *http.Request) string {
	host := req.Header.Get(XForwardedHost)
	if !CanTrustForwardedHeaders(req) || host == "" {
		host = req.Host
	}
	return host
}

// GetRequestURI return the request URI or X-Forwarded-Uri if present and the
// request came from a trusted reverse proxy.
func GetRequestURI(req *http.Request) string {
	uri := req.Header.Get(XForwardedURI)
	if !CanTrustForwardedHeaders(req) || uri == "" {
		// Use RequestURI to preserve ?query
		uri = req.URL.RequestURI()
	}
	return uri
}

// GetRequestPath returns the request URI or X-Forwarded-Uri if present and the
// request came from a trusted reverse proxy but always strips the query
// parameters and fragment suffixes and only returns the pure path.
func GetRequestPath(req *http.Request) string {
	uri := stripRequestFragment(GetRequestURI(req))

	// Parse URI and return only the path component
	if parsedURL, err := url.Parse(uri); err == nil {
		return stripRequestFragment(parsedURL.Path)
	}

	// Fallback: strip query parameters manually
	return stripRequestQuery(uri)
}

func stripRequestFragment(uri string) string {
	if idx := strings.Index(uri, "#"); idx != -1 {
		return uri[:idx]
	}

	return uri
}

func stripRequestQuery(uri string) string {
	if idx := strings.Index(uri, "?"); idx != -1 {
		return uri[:idx]
	}

	return uri
}

// CanTrustForwardedHeaders determines if forwarded headers should be processed
// based on the RequestScope and the direct caller's address.
func CanTrustForwardedHeaders(req *http.Request) bool {
	scope := middlewareapi.GetRequestScope(req)
	if scope == nil {
		return false
	}

	return scope.CanTrustForwardedHeaders(req)
}

func IsForwardedRequest(req *http.Request) bool {
	return CanTrustForwardedHeaders(req) &&
		req.Host != GetRequestHost(req)
}
