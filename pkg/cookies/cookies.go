package cookies

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// MakeCookie constructs a cookie from the given parameters,
// discovering the domain from the request if not specified.
func MakeCookie(req *http.Request, name string, value string, path string, domain string, httpOnly bool, secure bool, expiration time.Duration, now time.Time, sameSite http.SameSite) *http.Cookie {
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
		SameSite: sameSite,
	}
}

// MakeCookieFromOptions constructs a cookie based on the given *options.CookieOptions,
// value and creation time
func MakeCookieFromOptions(req *http.Request, name string, value string, opts *options.CookieOptions, expiration time.Duration, now time.Time) *http.Cookie {
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}

	// Sort cookie domains by length, so that we try longer (and more specific)
	// domains first
	sortedDomains := opts.CookieDomains
	sort.Slice(sortedDomains, func(i, j int) bool {
		return len(sortedDomains[i]) > len(sortedDomains[j])
	})
	for _, domain := range sortedDomains {
		if strings.HasSuffix(host, domain) {
			return MakeCookie(req, name, value, opts.CookiePath, domain, opts.CookieHTTPOnly, opts.CookieSecure, expiration, now, ParseSameSite(opts.CookieSameSite))
		}
	}
	// If nothing matches, create the cookie with the shortest domain
	logger.Printf("Warning: request host %q did not match any of the specific cookie domains of %q", host, strings.Join(sortedDomains, ","))
	defaultDomain := ""
	if len(sortedDomains) > 0 {
		defaultDomain = sortedDomains[len(sortedDomains)-1]
	}
	return MakeCookie(req, name, value, opts.CookiePath, defaultDomain, opts.CookieHTTPOnly, opts.CookieSecure, expiration, now, ParseSameSite(opts.CookieSameSite))
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
		return http.SameSiteDefaultMode
	default:
		panic(fmt.Sprintf("Invalid value for SameSite: %s", v))
	}
}
