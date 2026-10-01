package util

import (
	"errors"
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

// GetRequestPath returns a decoded path suitable for skip-auth matching, using
// X-Forwarded-Uri only for a trusted reverse proxy. An error means the path must
// not grant an authentication exemption. It does not modify the request URL.
func GetRequestPath(req *http.Request) (string, error) {
	uri := GetRequestURI(req)
	if !strings.HasPrefix(uri, "/") || strings.ContainsAny(uri, "# \t\r\n") {
		return "", errors.New("request target is not an unambiguous origin-form URI")
	}

	// Unlike url.Parse, ParseRequestURI keeps a leading // in the path.
	parsedURL, err := url.ParseRequestURI(uri)
	if err != nil {
		return "", errors.New("invalid request target")
	}
	requestPath := parsedURL.Path
	if strings.ContainsAny(requestPath, ";\\#?") || strings.Contains(requestPath, "//") {
		return "", errors.New("request path contains ambiguous separators")
	}
	for _, char := range requestPath {
		if char < 0x20 || char == 0x7f {
			return "", errors.New("request path contains a control character")
		}
	}
	for _, segment := range strings.Split(requestPath, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("request path contains a dot segment")
		}
	}
	return requestPath, nil
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
