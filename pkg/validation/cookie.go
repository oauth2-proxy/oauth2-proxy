package validation

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

func validateCookieOptions(o options.CookieOptions) []string {
	msgs := validateCookieSecret(o.Secret)

	if o.Refresh >= o.Expire {
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
	cookie := &http.Cookie{Name: name}
	if cookie.String() == "" {
		return []string{fmt.Sprintf("invalid cookie name: %q", name)}
	}
	return []string{}
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

	// If the secretBytes is different to the raw secret, it was decoded from Base64
	// Add a note to the error message
	var decodedSuffix string
	if string(secretBytes) != secret {
		decodedSuffix = " note: cookie secret was base64 decoded"
	}

	return []string{fmt.Sprintf(
		"cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is %d bytes.%s",
		len(secretBytes), decodedSuffix)}
}
