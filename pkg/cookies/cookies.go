package cookies

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/logger"
)

// MakeCookie constructs a cookie from the given parameters,
// discovering the domain from the request if not specified.
func MakeCookie(req *http.Request, name string, value string, path string, domain string, httpOnly bool, secure bool, expiration time.Duration, now time.Time) *http.Cookie {
	if domain != "" {
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !strings.HasSuffix(host, domain) {
			logger.Printf("Warning: request host is %q but using configured cookie domain of %q", host, domain)
		}
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   domain,
		HttpOnly: httpOnly,
		Secure:   secure,
		Expires:  now.Add(expiration),
	}
}

// MakeCookieFromOptions constructs a cookie based on the givemn *options.CookieOptions,
// value and creation time
func MakeCookieFromOptions(req *http.Request, name string, value string, opts *options.CookieOptions, expiration time.Duration, now time.Time) *http.Cookie {
	return MakeCookie(req, name, value, opts.CookiePath, opts.CookieDomain, opts.CookieHTTPOnly, opts.CookieSecure, expiration, now)
}
