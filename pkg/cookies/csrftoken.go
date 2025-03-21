package cookies

import (
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// MakeCSRFTokenCookieFromOptions constructs a cookie based on the given *options.CSRFToken,
// value and creation time
func MakeCSRFTokenCookieFromOptions(req *http.Request, name string, value string, opts *options.CSRFToken, expiration time.Duration, now time.Time) *http.Cookie {
	domain := GetCookieDomain(req, opts.CookieDomains)
	// If nothing matches, create the cookie with the shortest domain
	// We short cookie domains by length during validation, so last domain
	// is the shortest.
	if domain == "" && len(opts.CookieDomains) > 0 {
		logger.Errorf("Warning: request host %q did not match any of the specific cookie domains of %q",
			requestutil.GetRequestHost(req),
			strings.Join(opts.CookieDomains, ","),
		)
		domain = opts.CookieDomains[len(opts.CookieDomains)-1]
	}

	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     opts.CookiePath,
		Domain:   domain,
		HttpOnly: opts.CookieHTTPOnly,
		Secure:   opts.CookieSecure,
		SameSite: ParseSameSite(opts.CookieSameSite),
	}

	if expiration != time.Duration(0) {
		c.Expires = now.Add(expiration)
	}

	warnInvalidDomain(c, req)

	return c
}

func CSRFTokenCookieForSession(rw http.ResponseWriter, req *http.Request, opts *options.CSRFToken, token string) {
	csrfTokenCookie := MakeCSRFTokenCookieFromOptions(
		req,
		opts.CookieName,
		token,
		opts,
		opts.CookieExpire,
		time.Now())
	http.SetCookie(rw, csrfTokenCookie)
}
