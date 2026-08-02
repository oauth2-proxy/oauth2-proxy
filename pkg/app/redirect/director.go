package redirect

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// AppDirector is responsible for determining where OAuth2 Proxy should redirect
// a users request to after the user has authenticated with the identity provider.
type AppDirector struct {
	proxyPrefix string
	validator   *validator
}

// AppDirectorOpts are the requirements for constructing a new AppDirector.
type AppDirectorOpts struct {
	ProxyPrefix    string
	AllowedDomains []string
}

// NewAppDirector constructs a new AppDirector for getting the application
// redirect URL.
func NewAppDirector(opts AppDirectorOpts) *AppDirector {
	prefix := opts.ProxyPrefix
	if !strings.HasSuffix(prefix, "/") {
		prefix = fmt.Sprintf("%s/", prefix)
	}

	return &AppDirector{
		proxyPrefix: prefix,
		validator:   newValidator(opts.AllowedDomains),
	}
}

// IsValidRedirect checks whether the redirect URL is safe and allowed.
func (a *AppDirector) IsValidRedirect(redirect string) bool {
	return a.validator.isValidRedirect(redirect)
}

// GetRedirect determines the full URL or URI path to redirect clients to once
// authenticated with the OAuthProxy.
// Strategy priority (first legal result is used):
// - `rd` querysting parameter
// - `X-Auth-Request-Redirect` header
// - `X-Forwarded-(Proto|Host|Uri)` headers (when ReverseProxy mode is enabled)
// - `X-Forwarded-(Proto|Host)` if `Uri` has the ProxyPath (i.e. /oauth2/*)
// - `X-Forwarded-Uri` direct URI path (when ReverseProxy mode is enabled)
// - `req.URL.RequestURI` if not under the ProxyPath (i.e. /oauth2/*)
// - `/`
func (a *AppDirector) GetRedirect(req *http.Request) (string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", err
	}

	// These redirect getter functions are strategies ordered by priority
	// for figuring out the redirect URL.
	for _, rdGetter := range []redirectGetter{
		a.getRdQuerystringRedirect,
		a.getXAuthRequestRedirect,
		a.getXForwardedHeadersRedirect,
		a.getURIRedirect,
	} {
		redirect := rdGetter(req)
		// Call `p.IsValidRedirect` again here a final time to be safe
		if redirect != "" && a.validator.isValidRedirect(redirect) {
			return redirect, nil
		}
	}

	return "/", nil
}

// validateRedirect checks that the redirect is valid.
// When an invalid, non-empty redirect is found, an error will be logged using
// the provided format.
func (a *AppDirector) validateRedirect(redirect string, errorFormat string) string {
	if a.validator.isValidRedirect(redirect) {
		return redirect
	}
	if redirect != "" {
		logger.Errorf(errorFormat, redirect)
	}
	return ""
}

// hasProxyPrefix determines whether the obtained path would be a request to
// one of OAuth2 Proxy's own endpoints, e.g. the callback URL.
// Redirects to these endpoints should not be allowed as they will create
// redirection loops.
func (a *AppDirector) hasProxyPrefix(path string) bool {
	return strings.HasPrefix(path, a.proxyPrefix)
}
