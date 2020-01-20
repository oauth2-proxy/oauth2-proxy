package options

import "time"

// CookieOptions contains configuration options relating to Cookie configuration
type CookieOptions struct {
	CookieName     string        `flag:"cookie-name" cfg:"cookie_name" env:"OAUTH2_PROXY_COOKIE_NAME"`
	CookieSecret   string        `flag:"cookie-secret" cfg:"cookie_secret" env:"OAUTH2_PROXY_COOKIE_SECRET"`
	CookieDomain   string        `flag:"cookie-domain" cfg:"cookie_domain" env:"OAUTH2_PROXY_COOKIE_DOMAIN"`
	CookiePath     string        `flag:"cookie-path" cfg:"cookie_path" env:"OAUTH2_PROXY_COOKIE_PATH"`
	CookieExpire   time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"OAUTH2_PROXY_COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh" env:"OAUTH2_PROXY_COOKIE_REFRESH"`
	CookieSecure   bool          `flag:"cookie-secure" cfg:"cookie_secure" env:"OAUTH2_PROXY_COOKIE_SECURE"`
	CookieHTTPOnly bool          `flag:"cookie-httponly" cfg:"cookie_httponly" env:"OAUTH2_PROXY_COOKIE_HTTPONLY"`
	CookieSameSite string        `flag:"cookie-samesite" cfg:"cookie_samesite" env:"OAUTH2_PROXY_COOKIE_SAMESITE"`
}
