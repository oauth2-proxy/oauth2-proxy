package options

import (
	"time"

	mw "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/spf13/pflag"
)

// Cookie contains configuration options relating to Cookie configuration
type Cookie struct {
	Name    string        `flag:"cookie-name" cfg:"cookie_name"`
	Secret  string        `flag:"cookie-secret" cfg:"cookie_secret"`
	Domains []string      `flag:"cookie-domain" cfg:"cookie_domains"`
	Path    string        `flag:"cookie-path" cfg:"cookie_path"`
	Expire  time.Duration `flag:"cookie-expire" cfg:"cookie_expire"`

	InternalRefresh string            `flag:"cookie-refresh" cfg:"cookie_refresh"`
	Refresh         *mw.RefreshOption `cfg:",internal"`

	Secure   bool   `flag:"cookie-secure" cfg:"cookie_secure"`
	HTTPOnly bool   `flag:"cookie-httponly" cfg:"cookie_httponly"`
	SameSite string `flag:"cookie-samesite" cfg:"cookie_samesite"`
}

func cookieFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("cookie", pflag.ExitOnError)

	flagSet.String("cookie-name", "_oauth2_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.StringSlice("cookie-domain", []string{}, "Optional cookie domains to force cookies to (ie: `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match).")
	flagSet.String("cookie-path", "/", "an optional cookie path to force cookies to (ie: /poc/)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.String("cookie-refresh", "0s", "set cookie refresh, either a positive time duration or \"1%\" to \"100%\" of token expiration duration")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")
	flagSet.String("cookie-samesite", "", "set SameSite cookie attribute (ie: \"lax\", \"strict\", \"none\", or \"\"). ")

	return flagSet
}

// cookieDefaults creates a Cookie populating each field with its default value
func cookieDefaults() Cookie {
	return Cookie{
		Name:            "_oauth2_proxy",
		Secret:          "",
		Domains:         nil,
		Path:            "/",
		Expire:          time.Duration(168) * time.Hour,
		InternalRefresh: "0s",
		Secure:          true,
		HTTPOnly:        true,
		SameSite:        "",
	}
}
