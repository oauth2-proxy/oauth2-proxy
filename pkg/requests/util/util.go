package util

import (
	"net/http"

	"github.com/google/uuid"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

const (
	XForwardedProto = "X-Forwarded-Proto"
	XForwardedHost  = "X-Forwarded-Host"
	XForwardedURI   = "X-Forwarded-Uri"
	XRequestID      = "X-Request-Id"
)

// This is altered by SetRequestIDHeader to globally change the default
// RequestID Header.
var requestIDHeader = XRequestID

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

// GetRequestID gets an existing RequestID set on the request Scope.
func GetRequestID(req *http.Request) string {
	scope := middlewareapi.GetRequestScope(req)
	if scope != nil {
		return scope.RequestID
	}
	return GenRequestID(req)
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

// GenRequestID pulls the `X-Request-Id` header or makes a new random UUID
// if no header is set.
// This is only used for setting `middlewareapi.RequestScope.RequestID`.
// All other consumers should call `GetRequestID`.
func GenRequestID(req *http.Request) string {
	rid := req.Header.Get(requestIDHeader)
	if rid != "" {
		return rid
	}
	return uuid.New().String()
}

// SetRequestIDHeader sets the request header to fetch our Request IDs from
func SetRequestIDHeader(header string) {
	if header == "" {
		requestIDHeader = XRequestID
		return
	}
	requestIDHeader = header
}
