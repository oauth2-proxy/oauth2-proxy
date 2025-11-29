package options

import (
	"fmt"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

const (
	// DefaultCookieSecure is the default value for Cookie.Secure
	DefaultCookieSecure bool = true
	// DefaultCookieHTTPOnly is the default value for Cookie.HTTPOnly
	DefaultCookieHTTPOnly bool = true
	// DefaultCSRFPerRequest is the default value for Cookie.CSRFPerRequest
	DefaultCSRFPerRequest bool = false
)

// Cookie contains configuration options relating session and CSRF cookies
type Cookie struct {
	// Name is the name of the cookie
	Name string `yaml:"name,omitempty"`
	// Secret is the secret used to encrypt/sign the cookie value
	Secret string `yaml:"secret,omitempty"`
	// SecretFile is a file containing the secret used to encrypt/sign the cookie value
	// instead of specifying it directly in the config. Secret takes precedence over SecretFile
	SecretFile string `yaml:"secretFile,omitempty"`
	// Domains is a list of domains for which the cookie is valid
	Domains []string `yaml:"domains,omitempty"`
	// Path is the path for which the cookie is valid
	Path string `yaml:"path,omitempty"`
	// Expire is the duration before the cookie expires
	Expire time.Duration `yaml:"expire,omitempty"`
	// Refresh is the duration after which the cookie is refreshable
	Refresh time.Duration `yaml:"refresh,omitempty"`
	// Secure indicates whether the cookie is only sent over HTTPS
	Secure *bool `yaml:"secure,omitempty"`
	// HTTPOnly indicates whether the cookie is inaccessible to JavaScript
	HTTPOnly *bool `yaml:"httpOnly,omitempty"`
	// SameSite sets the SameSite attribute on the cookie
	SameSite string `yaml:"sameSite,omitempty"`
	// CSRFPerRequest indicates whether a unique CSRF token is generated for each request
	// Enables parallel requests from clients (e.g., multiple tabs)
	CSRFPerRequest *bool `yaml:"csrfPerRequest,omitempty"`
	// CSRFPerRequestLimit sets a limit on the number of valid CSRF tokens when CSRFPerRequest is enabled
	// Used to prevent unbounded memory growth from storing too many tokens
	CSRFPerRequestLimit int `yaml:"csrfPerRequestLimit,omitempty"`
	// CSRFExpire sets the duration before a CSRF token expires
	CSRFExpire time.Duration `yaml:"csrfExpire,omitempty"`
}

// GetSecret returns the cookie secret, reading from file if SecretFile is set
func (c *Cookie) GetSecret() (secret string, err error) {
	if c.Secret != "" || c.SecretFile == "" {
		return c.Secret, nil
	}

	fileSecret, err := os.ReadFile(c.SecretFile)
	if err != nil {
		return "", fmt.Errorf("error reading cookie secret file %s: %w", c.SecretFile, err)
	}

	return string(fileSecret), nil
}

// EnsureDefaults sets any default values for the Cookie configuration
func (c *Cookie) EnsureDefaults() {
	if c.Name == "" {
		c.Name = "_oauth2_proxy"
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Expire == 0 {
		c.Expire = time.Duration(168) * time.Hour
	}
	if c.Secure == nil {
		c.Secure = ptr.To(DefaultCookieSecure)
	}
	if c.HTTPOnly == nil {
		c.HTTPOnly = ptr.To(DefaultCookieHTTPOnly)
	}
	if c.CSRFPerRequest == nil {
		c.CSRFPerRequest = ptr.To(DefaultCSRFPerRequest)
	}
	if c.CSRFExpire == 0 {
		c.CSRFExpire = time.Duration(15) * time.Minute
	}
}
