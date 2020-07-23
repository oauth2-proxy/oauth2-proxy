package cookies

import (
	"fmt"
	"net"
	"net/http"
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
func MakeCookieFromOptions(req *http.Request, name string, value string, cookieOpts *options.Cookie, expiration time.Duration, now time.Time) *http.Cookie {
	domain := GetCookieDomain(req, cookieOpts.Domains)

	if domain != "" {
		return MakeCookie(req, name, value, cookieOpts.Path, domain, cookieOpts.HTTPOnly, cookieOpts.Secure, expiration, now, ParseSameSite(cookieOpts.SameSite))
	}
	// If nothing matches, create the cookie with the shortest domain
	logger.Printf("Warning: request host %q did not match any of the specific cookie domains of %q", GetRequestHost(req), strings.Join(cookieOpts.Domains, ","))
	defaultDomain := ""
	if len(cookieOpts.Domains) > 0 {
		defaultDomain = cookieOpts.Domains[len(cookieOpts.Domains)-1]
	}
	return MakeCookie(req, name, value, cookieOpts.Path, defaultDomain, cookieOpts.HTTPOnly, cookieOpts.Secure, expiration, now, ParseSameSite(cookieOpts.SameSite))
}

// GetCookieDomain returns the correct cookie domain given a list of domains
// by checking the X-Fowarded-Host and host header of an an http request
func GetCookieDomain(req *http.Request, cookieDomains []string) string {
	host := GetRequestHost(req)
	for _, domain := range cookieDomains {
		if strings.HasSuffix(host, domain) {
			return domain
		}
	}
	return ""
}

// GetRequestHost return the request host header or X-Forwarded-Host if present
func GetRequestHost(req *http.Request) string {
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}
	return host
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
