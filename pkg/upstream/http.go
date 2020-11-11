package upstream

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/yhat/wsutil"
)

const (
	// SignatureHeader is the name of the request header containing the GAP Signature
	// Part of hmacauth
	SignatureHeader = "GAP-Signature"

	httpScheme  = "http"
	httpsScheme = "https"
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
	u.Path = ""

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
	rw.Header().Set("GAP-Upstream-Address", h.upstream)
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

// newReverseProxy creates a new reverse proxy for proxying requests to upstream
// servers based on the upstream configuration provided.
// The proxy should render an error page if there are failures connecting to the
// upstream server.
func newReverseProxy(target *url.URL, upstream options.Upstream, errorHandler ProxyErrorHandler) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Configure options on the SingleHostReverseProxy
	if upstream.FlushInterval != nil {
		proxy.FlushInterval = upstream.FlushInterval.Duration()
	} else {
		proxy.FlushInterval = 1 * time.Second
	}

	// InsecureSkipVerify is a configurable option we allow
	/* #nosec G402 */
	if upstream.InsecureSkipTLSVerify {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Set the request director based on the PassHostHeader option
	if upstream.PassHostHeader != nil && !*upstream.PassHostHeader {
		setProxyUpstreamHostHeader(proxy, target)
	} else {
		setProxyDirector(proxy)
	}

	// Set the error handler so that upstream connection failures render the
	// error page instead of sending a empty response
	if errorHandler != nil {
		proxy.ErrorHandler = errorHandler
	}
	return proxy
}

// setProxyUpstreamHostHeader sets the proxy.Director so that upstream requests
// receive a host header matching the target URL.
func setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.Host = target.Host
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
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
	}
}

// newWebSocketReverseProxy creates a new reverse proxy for proxying websocket connections.
func newWebSocketReverseProxy(u *url.URL, skipTLSVerify bool) http.Handler {
	// This should create the correct scheme for insecure vs secure connections
	wsScheme := "ws" + strings.TrimPrefix(u.Scheme, "http")
	wsURL := &url.URL{Scheme: wsScheme, Host: u.Host}

	wsProxy := wsutil.NewSingleHostReverseProxy(wsURL)
	/* #nosec G402 */
	if skipTLSVerify {
		wsProxy.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return wsProxy
}
