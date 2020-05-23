package options

import (
	"time"

	"github.com/spf13/pflag"
)

// CookieOptions contains configuration options relating to Cookie configuration
type CookieOptions struct {
	Name     string        `flag:"cookie-name" cfg:"cookie_name"`
	Secret   string        `flag:"cookie-secret" cfg:"cookie_secret"`
	Domains  []string      `flag:"cookie-domain" cfg:"cookie_domains"`
	Path     string        `flag:"cookie-path" cfg:"cookie_path"`
	Expire   time.Duration `flag:"cookie-expire" cfg:"cookie_expire"`
	Refresh  time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh"`
	Secure   bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	HTTPOnly bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`
	SameSite string        `flag:"cookie-samesite" cfg:"cookie_samesite"`
}

func cookieFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("cookie", pflag.ExitOnError)

	flagSet.String("cookie-name", "_oauth2_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.StringSlice("cookie-domain", []string{}, "Optional cookie domains to force cookies to (ie: `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match).")
	flagSet.String("cookie-path", "/", "an optional cookie path to force cookies to (ie: /poc/)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")
	flagSet.String("cookie-samesite", "", "set SameSite cookie attribute (ie: \"lax\", \"strict\", \"none\", or \"\"). ")

	return flagSet
}

// defaultCookieOptions creates a CookieOptions populating each field with its default value
func defaultCookieOptions() CookieOptions {
	return CookieOptions{
		Name:     "_oauth2_proxy",
		Secret:   "",
		Domains:  nil,
		Path:     "/",
		Expire:   time.Duration(168) * time.Hour,
		Refresh:  time.Duration(0),
		Secure:   true,
		HTTPOnly: true,
		SameSite: "",
	}
}
