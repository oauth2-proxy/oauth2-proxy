package upstream

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

const (
	// SignatureHeader is the name of the request header containing the GAP Signature
	// Part of hmacauth
	SignatureHeader = "GAP-Signature"

	httpScheme  = "http"
	httpsScheme = "https"
	unixScheme  = "unix"
)

// SignatureHeaders contains the headers to be signed by the hmac algorithm
// Part of hmacauth
var SignatureHeaders = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Preferred-User",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Gap-Auth",
}

// newHTTPUpstreamProxy creates a new httpUpstreamProxy that can serve requests
// to a single upstream host.
func newHTTPUpstreamProxy(upstream options.Upstream, u *url.URL, sigData *options.SignatureData, errorHandler ProxyErrorHandler) http.Handler {
	// Set path to empty so that request paths start at the server root
	// Unix scheme need the path to find the socket
	if u.Scheme != "unix" {
		u.Path = ""
	}

	// Create a ReverseProxy
	proxy := newReverseProxy(u, upstream, errorHandler)

	// Set up a WebSocket proxy if required
	var wsProxy http.Handler
	if upstream.ProxyWebSockets == nil || *upstream.ProxyWebSockets {
		wsProxy = newWebSocketReverseProxy(u, upstream.InsecureSkipTLSVerify)
	}

	var auth hmacauth.HmacAuth
	if sigData != nil {
		auth = hmacauth.NewHmacAuth(sigData.Hash, []byte(sigData.Key), SignatureHeader, SignatureHeaders)
	}

	return &httpUpstreamProxy{
		upstream:  upstream.ID,
		handler:   proxy,
		wsHandler: wsProxy,
		auth:      auth,
	}
}

// httpUpstreamProxy represents a single HTTP(S) upstream proxy
type httpUpstreamProxy struct {
	upstream  string
	handler   http.Handler
	wsHandler http.Handler
	auth      hmacauth.HmacAuth
}

// ServeHTTP proxies requests to the upstream provider while signing the
// request headers
func (h *httpUpstreamProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	scope := middleware.GetRequestScope(req)
	// If scope is nil, this will panic.
	// A scope should always be injected before this handler is called.
	scope.Upstream = h.upstream

	// TODO (@NickMeves) - Deprecate GAP-Signature & remove GAP-Auth
	if h.auth != nil {
		req.Header.Set("GAP-Auth", rw.Header().Get("GAP-Auth"))
		h.auth.SignRequest(req)
	}
	if h.wsHandler != nil && strings.EqualFold(req.Header.Get("Connection"), "upgrade") && req.Header.Get("Upgrade") == "websocket" {
		h.wsHandler.ServeHTTP(rw, req)
	} else {
		h.handler.ServeHTTP(rw, req)
	}
}

// Unix implementation of http.RoundTripper, required to register unix protocol in reverse proxy
type unixRoundTripper struct {
	Transport *http.Transport
}

// Implementation of https://pkg.go.dev/net/http#RoundTripper interface to support http protocol over unix socket
func (t *unixRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Inspired by https://github.com/tv42/httpunix
	// Not having a Host, even if not used, makes the reverseproxy fail with a "no Host in request URL"
	if req.Host == "" {
		req.Host = "localhost"
	}
	req.URL.Host = req.Host
	tt := t.Transport
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	return tt.RoundTrip(req)
}

// newReverseProxy creates a new reverse proxy for proxying requests to upstream
// servers based on the upstream configuration provided.
// The proxy should render an error page if there are failures connecting to the
// upstream server.
func newReverseProxy(target *url.URL, upstream options.Upstream, errorHandler ProxyErrorHandler) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Inherit default transport options from Go's stdlib
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if target.Scheme == "unix" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, target.Scheme, target.Path)
		}
		transport.RegisterProtocol(target.Scheme, &unixRoundTripper{Transport: transport})
	}

	// Change default duration for waiting for an upstream response
	if upstream.Timeout != nil {
		transport.ResponseHeaderTimeout = *upstream.Timeout
	}

	// Configure options on the SingleHostReverseProxy
	if upstream.FlushInterval != nil {
		proxy.FlushInterval = *upstream.FlushInterval
	} else {
		proxy.FlushInterval = options.DefaultUpstreamFlushInterval
	}

	// InsecureSkipVerify is a configurable option we allow
	/* #nosec G402 */
	if upstream.InsecureSkipTLSVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// Ensure we always pass the original request path
	setProxyDirector(proxy)

	if upstream.PassHostHeader != nil && !*upstream.PassHostHeader {
		setProxyUpstreamHostHeader(proxy, target)
	}

	// Set the error handler so that upstream connection failures render the
	// error page instead of sending a empty response
	if errorHandler != nil {
		proxy.ErrorHandler = errorHandler
	}

	// Apply the customized transport to our proxy before returning it
	proxy.Transport = transport

	return proxy
}

// setProxyUpstreamHostHeader sets the proxy.Director so that upstream requests
// receive a host header matching the target URL.
func setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host
	}
}

// setProxyDirector sets the proxy.Director so that request URIs are escaped
// when proxying to usptream servers.
func setProxyDirector(proxy *httputil.ReverseProxy) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
		req.URL.ForceQuery = false
	}
}

// newWebSocketReverseProxy creates a new reverse proxy for proxying websocket connections.
func newWebSocketReverseProxy(u *url.URL, skipTLSVerify bool) http.Handler {
	wsProxy := httputil.NewSingleHostReverseProxy(u)

	// Inherit default transport options from Go's stdlib
	transport := http.DefaultTransport.(*http.Transport).Clone()

	/* #nosec G402 */
	if skipTLSVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// Apply the customized transport to our proxy before returning it
	wsProxy.Transport = transport

	return wsProxy
}
