package cookies

import (
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

// BuildSessionCookieOptions constructs the session cookie options
func BuildSessionCookieOptions(name string, value string, opts *options.Cookie, expiration time.Duration, now time.Time) *CookieOptions {
	cookieOptions := &CookieOptions{
		Name:       name,
		Value:      value,
		Domains:    opts.Domains,
		Expiration: expiration,
		Now:        now,
		SameSite:   opts.SameSite,
		Path:       opts.Path,
		HTTPOnly:   opts.HTTPOnly,
		Secure:     opts.Secure,
	}
	return cookieOptions
}

// MakeSessionCookie encodes the CSRF to a signed cookie and sets it on the ResponseWriter
func MakeSessionCookie(req *http.Request, name string, value string, opts *options.Cookie, expiration time.Duration, now time.Time) *http.Cookie {
	sessionCookieOptions := BuildSessionCookieOptions(
		name,
		value,
		opts,
		expiration,
		now)
	return MakeCookieFromOptions(req, sessionCookieOptions)
}
