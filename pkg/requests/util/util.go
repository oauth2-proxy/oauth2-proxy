package util

import (
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

const (
	XForwardedProto = "X-Forwarded-Proto"
	XForwardedHost  = "X-Forwarded-Host"
	XForwardedURI   = "X-Forwarded-Uri"
)

// GetRequestProto returns the request scheme or X-Forwarded-Proto if present
// and the request is proxied.
func GetRequestProto(req *http.Request) string {
	proto := req.Header.Get(XForwardedProto)
	if !IsProxied(req) || proto == "" {
		proto = req.URL.Scheme
	}
	return proto
}

// GetRequestHost returns the request host header or X-Forwarded-Host if
// present and the request is proxied.
func GetRequestHost(req *http.Request) string {
	host := req.Header.Get(XForwardedHost)
	if !IsProxied(req) || host == "" {
		host = req.Host
	}
	return host
}

// GetRequestURI return the request URI or X-Forwarded-Uri if present and the
// request is proxied.
func GetRequestURI(req *http.Request) string {
	uri := req.Header.Get(XForwardedURI)
	if !IsProxied(req) || uri == "" {
		// Use RequestURI to preserve ?query
		uri = req.URL.RequestURI()
	}
	return uri
}

// IsProxied determines if a request was from a proxy based on the RequestScope
// ReverseProxy tracker.
func IsProxied(req *http.Request) bool {
	scope := middlewareapi.GetRequestScope(req)
	if scope == nil {
		return false
	}
	return scope.ReverseProxy
}

func IsForwardedRequest(req *http.Request) bool {
	return IsProxied(req) &&
		req.Host != GetRequestHost(req)
}
