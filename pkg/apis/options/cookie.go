package options

import (
	"time"
)

// Cookie contains configuration options relevant for the CSRF and authentication cookies
type Cookie struct {
	Name           string        `yaml:"name,omitempty"`
	Secret         string        `yaml:"secret,omitempty"`
	Domains        []string      `yaml:"domains,omitempty"`
	Path           string        `yaml:"path,omitempty"`
	Expire         time.Duration `yaml:"expire,omitempty"`
	Refresh        time.Duration `yaml:"refresh,omitempty"`
	Secure         bool          `yaml:"secure,omitempty"`
	HTTPOnly       bool          `yaml:"httpOnly,omitempty"`
	SameSite       string        `yaml:"sameSite,omitempty"`
	CSRFPerRequest bool          `yaml:"csrfPerRequest,omitempty"`
	CSRFExpire     time.Duration `yaml:"csrfExpire,omitempty"`
}

// cookieDefaults creates a Cookie populating each field with its default value
func cookieDefaults() Cookie {
	return Cookie{
		Name:           "_oauth2_proxy",
		Secret:         "",
		Domains:        nil,
		Path:           "/",
		Expire:         time.Duration(168) * time.Hour,
		Refresh:        time.Duration(0),
		Secure:         true,
		HTTPOnly:       true,
		SameSite:       "",
		CSRFPerRequest: false,
		CSRFExpire:     time.Duration(15) * time.Minute,
	}
}
