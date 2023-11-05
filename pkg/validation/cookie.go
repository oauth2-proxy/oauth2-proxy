package validation

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

func validateCookie(o options.Cookie) []string {
	msgs := validateCookieSecret(o.Secret)

	if o.Expire != time.Duration(0) && o.Refresh >= o.Expire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%q) must be less than cookie_expire (%q)",
			o.Refresh.String(),
			o.Expire.String()))
	}

	switch o.SameSite {
	case "", "none", "lax", "strict":
	default:
		msgs = append(msgs, fmt.Sprintf("cookie_samesite (%q) must be one of ['', 'lax', 'strict', 'none']", o.SameSite))
	}

	// Sort cookie domains by length, so that we try longer (and more specific) domains first
	sort.Slice(o.Domains, func(i, j int) bool {
		return len(o.Domains[i]) > len(o.Domains[j])
	})

	msgs = append(msgs, validateCookieName(o.Name)...)
	return msgs
}

func validateCookieName(name string) []string {
	msgs := []string{}

	cookie := &http.Cookie{Name: name}
	if cookie.String() == "" {
		msgs = append(msgs, fmt.Sprintf("invalid cookie name: %q", name))
	}

	if len(name) > 256 {
		msgs = append(msgs, fmt.Sprintf("cookie name should be under 256 characters: cookie name is %d characters", len(name)))
	}
	return msgs
}

func validateCookieSecret(secret string) []string {
	if secret == "" {
		return []string{"missing setting: cookie-secret"}
	}

	secretBytes := encryption.SecretBytes(secret)
	// Check if the secret is a valid length
	switch len(secretBytes) {
	case 16, 24, 32:
		// Valid secret size found
		return []string{}
	}
	// Invalid secret size found, return a message
	return []string{fmt.Sprintf(
		"cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is %d bytes",
		len(secretBytes)),
	}
}
