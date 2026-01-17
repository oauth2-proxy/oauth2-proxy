package options

import (
	"fmt"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"go.yaml.in/yaml/v3"
)

const (
	// DefaultCookieInsecure is the default value for Cookie.Insecure
	DefaultCookieInsecure bool = false
	// DefaultCSRFPerRequest is the default value for Cookie.CSRFPerRequest
	DefaultCSRFPerRequest bool = false
)

// SameSiteMode is an enum representing the different SameSite modes for cookies
// Available modes are "Lax", "Strict", "None", and "" (default browser behavior)
type SameSiteMode string

const (
	SameSiteLax     SameSiteMode = "Lax"
	SameSiteStrict  SameSiteMode = "Strict"
	SameSiteNone    SameSiteMode = "None"
	SameSiteDefault SameSiteMode = ""
)

// ScriptAccess is an enum representing whether a cookie is accessible to JavaScript
// Available modes are "Allow", "Deny" (default behavior)
type ScriptAccess string

const (
	ScriptAccessDenied  ScriptAccess = "Deny"
	ScriptAccessAllowed ScriptAccess = "Allow"
	ScriptAccessNone    ScriptAccess = ""
)

// Cookie contains configuration options relating session and CSRF cookies
type Cookie struct {
	// Name is the name of the cookie
	Name string `yaml:"name,omitempty"`
	// Secret is the secret source used to encrypt/sign the cookie value
	Secret *SecretSource `yaml:"secret,omitempty"`
	// Domains is a list of domains for which the cookie is valid
	Domains []string `yaml:"domains,omitempty"`
	// Path is the path for which the cookie is valid
	Path string `yaml:"path,omitempty"`
	// Expire is the duration before the cookie expires
	Expire time.Duration `yaml:"expire,omitempty"`
	// Insecure indicates whether the cookie allows to be sent over HTTP
	// Default is false, which requires HTTPS
	Insecure *bool `yaml:"insecure,omitempty"`
	// ScriptAccess is a wrapper enum for HTTPOnly; indicates whether the
	// cookie is accessible to JavaScript. Default is deny which translates
	// to true for HTTPOnly, which helps mitigate certain XSS attacks
	ScriptAccess ScriptAccess `yaml:"scriptAccess,omitempty"`
	// SameSite sets the SameSite attribute on the cookie
	SameSite SameSiteMode `yaml:"sameSite,omitempty"`
	// CSRFPerRequest indicates whether a unique CSRF token is generated for each request
	// Enables parallel requests from clients (e.g., multiple tabs)
	// Default is false, which uses a single CSRF token per session
	CSRFPerRequest *bool `yaml:"csrfPerRequest,omitempty"`
	// CSRFPerRequestLimit sets a limit on the number of valid CSRF tokens when CSRFPerRequest is enabled
	// Used to prevent unbounded memory growth from storing too many tokens
	CSRFPerRequestLimit int `yaml:"csrfPerRequestLimit,omitempty"`
	// CSRFExpire sets the duration before a CSRF token expires
	CSRFExpire time.Duration `yaml:"csrfExpire,omitempty"`
}

// UnmarshalYAML unmarshalles the strings provided for the
// SameSite property to the enum type SameSiteMode
func (m *SameSiteMode) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch SameSiteMode(s) {
	case SameSiteLax, SameSiteStrict, SameSiteNone, SameSiteDefault:
		*m = SameSiteMode(s)
		return nil
	default:
		return fmt.Errorf("invalid same site mode: %s", s)
	}
}

// UnmarshalYAML unmarshalles the strings provided for the
// ScriptAccess property to the enum type ScriptAccess
func (sa *ScriptAccess) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch ScriptAccess(s) {
	case ScriptAccessAllowed, ScriptAccessDenied, ScriptAccessNone:
		*sa = ScriptAccess(s)
		return nil
	default:
		return fmt.Errorf("invalid script access: %s", s)
	}
}

// GetSecret returns the cookie secret as a string from the SecretSource
func (c *Cookie) GetSecret() (string, error) {
	secret, err := c.Secret.GetRawSecretValue()
	if err != nil {
		return "", fmt.Errorf("error getting cookie secret: %w", err)
	}

	return string(secret), nil
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
	if c.Secret == nil {
		c.Secret = &SecretSource{}
	}
	if c.Insecure == nil {
		c.Insecure = ptr.To(DefaultCookieInsecure)
	}
	if c.ScriptAccess == ScriptAccessNone {
		c.ScriptAccess = ScriptAccessDenied
	}
	if c.CSRFPerRequest == nil {
		c.CSRFPerRequest = ptr.To(DefaultCSRFPerRequest)
	}
	if c.CSRFExpire == 0 {
		c.CSRFExpire = time.Duration(15) * time.Minute
	}
}
