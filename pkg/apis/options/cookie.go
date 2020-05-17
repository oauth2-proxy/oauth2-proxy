package options

import "time"

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
