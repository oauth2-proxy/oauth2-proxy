package options

import (
	"errors"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/spf13/pflag"
)

// Cookie contains configuration options relating to Cookie configuration
type Cookie struct {
	Name                        string        `flag:"cookie-name" cfg:"cookie_name"`
	Secret                      string        `flag:"cookie-secret" cfg:"cookie_secret"`
	SecretFile                  string        `flag:"cookie-secret-file" cfg:"cookie_secret_file"`
	Domains                     []string      `flag:"cookie-domain" cfg:"cookie_domains"`
	Path                        string        `flag:"cookie-path" cfg:"cookie_path"`
	Expire                      time.Duration `flag:"cookie-expire" cfg:"cookie_expire"`
	Refresh                     time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh"`
	Secure                      bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	HTTPOnly                    bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`
	SameSite                    string        `flag:"cookie-samesite" cfg:"cookie_samesite"`
	CSRFPerRequest              bool          `flag:"cookie-csrf-per-request" cfg:"cookie_csrf_per_request"`
	CSRFPerRequestLimit         int           `flag:"cookie-csrf-per-request-limit" cfg:"cookie_csrf_per_request_limit"`
	CSRFExpire                  time.Duration `flag:"cookie-csrf-expire" cfg:"cookie_csrf_expire"`
	SessionRefreshLockDuration  time.Duration `flag:"session-refresh-lock-duration" cfg:"session_refresh_lock_duration"`
	SessionRefreshObtainTimeout time.Duration `flag:"session-refresh-obtain-timeout" cfg:"session_refresh_obtain_timeout"`
	SessionRefreshRetryPeriod   time.Duration `flag:"session-refresh-retry-period" cfg:"session_refresh_retry_period"`
}

func cookieFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("cookie", pflag.ExitOnError)

	flagSet.String("cookie-name", "_oauth2_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.String("cookie-secret-file", "", "For defining a separate cookie secret file to read the encryption key from")
	flagSet.StringSlice("cookie-domain", []string{}, "Optional cookie domains to force cookies to (ie: `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match).")
	flagSet.String("cookie-path", "/", "an optional cookie path to force cookies to (ie: /poc/)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")
	flagSet.String("cookie-samesite", "", "set SameSite cookie attribute (ie: \"lax\", \"strict\", \"none\", or \"\"). ")
	flagSet.Bool("cookie-csrf-per-request", false, "When this property is set to true, then the CSRF cookie name is built based on the state and varies per request. If property is set to false, then CSRF cookie has the same name for all requests.")
	flagSet.Int("cookie-csrf-per-request-limit", 0, "Sets a limit on the number of CSRF requests cookies that oauth2-proxy will create. The oldest cookies will be removed. Useful if users end up with 431 Request headers too large status codes.")
	flagSet.Duration("cookie-csrf-expire", time.Duration(15)*time.Minute, "expire timeframe for CSRF cookie")
	flagSet.Duration("session-refresh-lock-duration", time.Duration(2)*time.Second, "maximum time allowed for a session refresh attempt; if the refresh request isn't finished within this time, the lock will be released")
	flagSet.Duration("session-refresh-obtain-timeout", time.Duration(5)*time.Second, "timeout when attempting to obtain the session lock; if the lock is not obtained before this timeout, the refresh attempt will fail")
	flagSet.Duration("session-refresh-retry-period", time.Duration(10)*time.Millisecond, "how long to wait after failing to obtain the lock before trying again")
	return flagSet
}

// cookieDefaults creates a Cookie populating each field with its default value
func cookieDefaults() Cookie {
	return Cookie{
		Name:                        "_oauth2_proxy",
		Secret:                      "",
		SecretFile:                  "",
		Domains:                     nil,
		Path:                        "/",
		Expire:                      time.Duration(168) * time.Hour,
		Refresh:                     time.Duration(0),
		Secure:                      true,
		HTTPOnly:                    true,
		SameSite:                    "",
		CSRFPerRequest:              false,
		CSRFPerRequestLimit:         0,
		CSRFExpire:                  time.Duration(15) * time.Minute,
		SessionRefreshLockDuration:  time.Duration(2) * time.Second,
		SessionRefreshObtainTimeout: time.Duration(5) * time.Second,
		SessionRefreshRetryPeriod:   time.Duration(10) * time.Millisecond,
	}
}

// GetSecret returns the cookie secret, reading from file if SecretFile is set
func (c *Cookie) GetSecret() (secret string, err error) {
	if c.Secret != "" || c.SecretFile == "" {
		return c.Secret, nil
	}

	fileSecret, err := os.ReadFile(c.SecretFile)
	if err != nil {
		logger.Errorf("error reading cookie secret file %s: %s", c.SecretFile, err)
		return "", errors.New("could not read cookie secret file")
	}

	return string(fileSecret), nil
}
