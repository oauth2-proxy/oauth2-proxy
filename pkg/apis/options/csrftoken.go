package options

import (
	"time"

	"github.com/spf13/pflag"
)

type CSRFToken struct {
	CSRFToken      bool          `flag:"csrftoken" cfg:"csrftoken"`
	CookieName     string        `flag:"csrftoken-cookie-name" cfg:"csrftoken_cookie_name"`
	CookieDomains  []string      `flag:"csrftoken-cookie-domain" cfg:"csrftoken_cookie_domain"`
	CookiePath     string        `flag:"csrftoken-cookie-path" cfg:"csrftoken_cookie_path"`
	CookieExpire   time.Duration `flag:"csrftoken-cookie-expire" cfg:"csrftoken_cookie_expire"`
	CookieSecure   bool          `flag:"csrftoken-cookie-secure" cfg:"csrftoken_cookie_secure"`
	CookieHTTPOnly bool          `flag:"csrftoken-cookie-httponly" cfg:"csrftoken_cookie_httponly"`
	CookieSameSite string        `flag:"csrftoken-cookie-samesite" cfg:"csrftoken_cookie_samesite"`
	RequestHeader  string        `flag:"csrftoken-header" cfg:"csrftoken_header"`
}

func csrfTokenFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("csrftoken", pflag.ExitOnError)

	flagSet.Bool("csrftoken", false, "enable the CSRF token generation")
	flagSet.String("csrftoken-cookie-name", "_oauth2_proxy_csrftoken", "the name of the CSRF token cookie that the oauth2-proxy creates. If set to empty string, no CSRF cookie will be created for the session.")
	flagSet.StringSlice("csrftoken-cookie-domain", []string{}, "the domain(s) of the CSRF token cookie (ie: `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match).")
	flagSet.String("csrftoken-cookie-path", "/", "the path of the CSRF token cookie (ie: /poc/)*")
	flagSet.Duration("csrftoken-cookie-expire", time.Duration(168)*time.Hour, "expiration timeframe for the CSRF token cookie")
	flagSet.Bool("csrftoken-cookie-secure", true, "set secure (HTTPS) cookie flag for CSRF token cookie")
	flagSet.Bool("csrftoken-cookie-httponly", false, "set HttpOnly cookie flag for CSRF token cookie")
	flagSet.String("csrftoken-cookie-samesite", "strict", "set SameSite cookie attribute for CSRF token cookie (ie: \"lax\", \"strict\", \"none\", or \"\"). ")
	flagSet.String("csrftoken-header", "X-CSRF-Token", "The name of the header for holding the CSRF token sent from the client")
	return flagSet
}

func CSRFTokenDefaults() CSRFToken {
	return CSRFToken{
		CSRFToken:      false,
		CookieName:     "_oauth2_proxy_csrftoken",
		CookieDomains:  nil,
		CookiePath:     "/",
		CookieExpire:   time.Duration(168) * time.Hour,
		CookieSecure:   true,
		CookieHTTPOnly: false,
		CookieSameSite: "strict",
		RequestHeader:  "X-CSRF-Token",
	}
}
