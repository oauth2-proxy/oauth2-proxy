package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
)

type scopeKey string

// RequestScopeKey uses a typed string to reduce likelihood of clashing
// with other context keys
const RequestScopeKey scopeKey = "request-scope"

// RequestScope contains information regarding the request that is being made.
// The RequestScope is used to pass information between different middlewares
// within the chain.
type RequestScope struct {
	// ReverseProxy tracks whether OAuth2-Proxy is operating in reverse proxy
	// mode and if request `X-Forwarded-*` headers may be trusted
	ReverseProxy bool

	// TrustedProxies tracks which direct callers are allowed to supply
	// forwarded headers when ReverseProxy mode is enabled.
	TrustedProxies *ip.NetSet

	// RequestID is set to the request's `X-Request-Id` header if set.
	// Otherwise a random UUID is set.
	RequestID string

	// Session details the authenticated users information (if it exists).
	Session *sessions.SessionState

	// SaveSession indicates whether the session storage should attempt to save
	// the session or not.
	SaveSession bool

	// ClearSession indicates whether the user should be logged out or not.
	ClearSession bool

	// SessionRevalidated indicates whether the session has been revalidated since
	// it was loaded or not.
	SessionRevalidated bool

	// Upstream tracks which upstream was used for this request
	Upstream string
}

// GetRequestScope returns the current request scope from the given request
func GetRequestScope(req *http.Request) *RequestScope {
	scope := req.Context().Value(RequestScopeKey)
	if scope == nil {
		return nil
	}

	return scope.(*RequestScope)
}

// AddRequestScope adds a RequestScope to a request
func AddRequestScope(req *http.Request, scope *RequestScope) *http.Request {
	ctx := context.WithValue(req.Context(), RequestScopeKey, scope)
	return req.WithContext(ctx)
}

// CanTrustForwardedHeaders returns whether forwarded headers should be
// processed for this request.
func (s *RequestScope) CanTrustForwardedHeaders(req *http.Request) bool {
	if s == nil || req == nil || !s.ReverseProxy || s.TrustedProxies == nil {
		return false
	}

	if isUnixSocketRemoteAddr(req.RemoteAddr) {
		return true
	}

	remoteIP := parseRemoteAddrIP(req.RemoteAddr)
	if remoteIP == nil {
		return false
	}

	return s.TrustedProxies.Has(remoteIP)
}

func parseRemoteAddrIP(remoteAddr string) net.IP {
	if remoteAddr == "" {
		return nil
	}

	if ip := net.ParseIP(remoteAddr); ip != nil {
		return ip
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil
	}

	return net.ParseIP(host)
}

func isUnixSocketRemoteAddr(remoteAddr string) bool {
	return remoteAddr == "@" || strings.HasPrefix(remoteAddr, "/")
}
