package options

import (
	"time"
)

// Cookie contains configuration options relevant for the CSRF and authentication cookies
type Cookie struct {
	Name           string        `json:"name,omitempty"`
	Secret         string        `json:"secret,omitempty"`
	Domains        []string      `json:"domains,omitempty"`
	Path           string        `json:"path,omitempty"`
	Expire         time.Duration `json:"expire,omitempty"`
	Refresh        time.Duration `json:"refresh,omitempty"`
	Secure         bool          `json:"secure"`
	HTTPOnly       bool          `json:"httpOnly"`
	SameSite       string        `json:"sameSite,omitempty"`
	CSRFPerRequest bool          `json:"csrfPerRequest,omitempty"`
	CSRFExpire     time.Duration `json:"csrfExpire,omitempty"`
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
