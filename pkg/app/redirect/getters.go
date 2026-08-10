package redirect

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// redirectGetter represents a method to allow the proxy to determine a redirect
// based on the original request.
type redirectGetter func(req *http.Request) string

// getRdQuerystringRedirect handles this getAppRedirect strategy:
// - `rd` querysting parameter
func (a *appDirector) getRdQuerystringRedirect(req *http.Request) string {
	rd := req.Form.Get("rd")
	redirect := a.validateRedirect(rd,
		"Invalid redirect provided in rd querystring parameter: %s",
	)
	if redirect != "" {
		return redirect
	}

	// If `rd` is an absolute http(s) URL that was rejected because its host is
	// not on the whitelist, fall back to its path component when it targets the
	// same host the request was served on. See getRdPathRedirect for details.
	return a.getRdPathRedirect(req, rd)
}

// getRdPathRedirect extracts the path (and query) of an absolute http(s) `rd`
// redirect and validates it as a relative redirect, but only when the `rd`
// URL's host matches the host the request was served on.
//
// Reverse-proxy / forward_auth setups (e.g. Caddy `forward_auth` and nginx
// `auth_request`) build the post-login redirect as `{scheme}://{host}{uri}`,
// an absolute URL for the same host the client used to reach the proxy. The
// Caddy integration docs do not mention that such hosts must also be added to
// `--whitelist-domain`, so without that option the absolute `rd` is rejected
// and, because the `sign_in`/`start` requests are served under the proxy
// prefix, the remaining redirect strategies collapse to "/" — silently losing
// the originally requested URL (and its query) after login.
//
// Falling back to the path component is safe: it is a same-origin relative
// redirect, it is still run through the validator (so open-redirect protections
// such as "//" and "/../" still apply), and a `rd` pointing at a different,
// non-whitelisted host is left untouched so the other strategies can run.
func (a *appDirector) getRdPathRedirect(req *http.Request, rd string) string {
	if rd == "" || (!strings.HasPrefix(rd, "http://") && !strings.HasPrefix(rd, "https://")) {
		return ""
	}
	rdURL, err := url.Parse(rd)
	if err != nil || rdURL.Host == "" {
		return ""
	}
	if rdURL.Host != requestutil.GetRequestHost(req) {
		return ""
	}
	return a.validateRedirect(rdURL.RequestURI(),
		"Invalid redirect extracted from rd querystring parameter: %s",
	)
}

// getXAuthRequestRedirect handles this getAppRedirect strategy:
// - `X-Auth-Request-Redirect` Header
func (a *appDirector) getXAuthRequestRedirect(req *http.Request) string {
	return a.validateRedirect(
		req.Header.Get("X-Auth-Request-Redirect"),
		"Invalid redirect provided in X-Auth-Request-Redirect header: %s",
	)
}

// getXForwardedHeadersRedirect handles these getAppRedirect strategies:
// - `X-Forwarded-(Proto|Host|Uri)` headers (when ReverseProxy mode is enabled)
// - `X-Forwarded-(Proto|Host)` if `Uri` has the ProxyPath (i.e. /oauth2/*)
func (a *appDirector) getXForwardedHeadersRedirect(req *http.Request) string {
	if !requestutil.IsForwardedRequest(req) {
		return ""
	}

	uri := requestutil.GetRequestURI(req)
	if a.hasProxyPrefix(uri) {
		uri = "/"
	}

	redirect := fmt.Sprintf(
		"%s://%s%s",
		requestutil.GetRequestProto(req),
		requestutil.GetRequestHost(req),
		uri,
	)

	return a.validateRedirect(redirect,
		"Invalid redirect generated from X-Forwarded-* headers: %s")
}

// getURIRedirect handles these getAppRedirect strategies:
// - `X-Forwarded-Uri` direct URI path (when ReverseProxy mode is enabled)
// - `req.URL.RequestURI` if not under the ProxyPath (i.e. /oauth2/*)
// - `/`
func (a *appDirector) getURIRedirect(req *http.Request) string {
	redirect := a.validateRedirect(
		requestutil.GetRequestURI(req),
		"Invalid redirect generated from X-Forwarded-Uri header: %s",
	)
	if redirect == "" {
		redirect = req.URL.RequestURI()
	}

	if a.hasProxyPrefix(redirect) {
		return "/"
	}
	return redirect
}
