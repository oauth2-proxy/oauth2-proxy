package cookies

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// MakeCookieFromOptions constructs a cookie based on the given *options.CookieOptions,
// value and creation time
func MakeCookieFromOptions(req *http.Request, name string, value string, opts *options.Cookie, expiration time.Duration, now time.Time) *http.Cookie {
	domain := GetCookieDomain(req, opts.Domains)
	// If nothing matches, create the cookie with the shortest domain
	if domain == "" && len(opts.Domains) > 0 {
		logger.Errorf("Warning: request host %q did not match any of the specific cookie domains of %q",
			requestutil.GetRequestHost(req),
			strings.Join(opts.Domains, ","),
		)
		domain = opts.Domains[len(opts.Domains)-1]
	}

	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     opts.Path,
		Domain:   domain,
		HttpOnly: opts.HTTPOnly,
		Secure:   opts.Secure,
		SameSite: ParseSameSite(opts.SameSite),
	}

	if expiration != time.Duration(0) {
		c.Expires = now.Add(expiration)
	}

	warnInvalidDomain(c, req)

	return c
}

// GetCookieDomain returns the correct cookie domain given a list of domains
// by checking the X-Fowarded-Host and host header of an an http request
func GetCookieDomain(req *http.Request, cookieDomains []string) string {
	host := requestutil.GetRequestHost(req)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, domain := range cookieDomains {
		if strings.HasSuffix(host, domain) {
			return domain
		}
	}
	return ""
}

// Parse a valid http.SameSite value from a user supplied string for use of making cookies.
func ParseSameSite(v string) http.SameSite {
	switch v {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "":
		return 0
	default:
		panic(fmt.Sprintf("Invalid value for SameSite: %s", v))
	}
}

// warnInvalidDomain logs a warning if the request host and cookie domain are
// mismatched.
func warnInvalidDomain(c *http.Cookie, req *http.Request) {
	if c.Domain == "" {
		return
	}

	host := requestutil.GetRequestHost(req)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.HasSuffix(host, c.Domain) {
		logger.Errorf("Warning: request host is %q but using configured cookie domain of %q", host, c.Domain)
	}
}
