package validation

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

func validateCookie(o options.Cookie) []string {
	msgs := validateCookieSecret(o.Secret, o.SecretFile)

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

	msgs = append(msgs, validateCookieNamePrefix(o)...)
	return msgs
}

func validateCookieNamePrefix(o options.Cookie) []string {
	msgs := []string{}
	maxLength := 256 - 64 - 1 // -64 for hex(sha256(providerId)) length and -1 for underscore( _ separator)

	ctx := context.Background()
	cookieName := cookies.CookieName(utils.AppendProviderIDToContext(ctx, "test_provider"), &o)

	cookie := &http.Cookie{Name: cookieName}
	if cookie.String() == "" {
		msgs = append(msgs, fmt.Sprintf("invalid cookie name prefix: %q", o.Name))
	}

	if len(o.Name) > maxLength {
		msgs = append(msgs, fmt.Sprintf("cookie name prefix should be under %d characters: cookie name prefix is %d characters", maxLength, len(o.Name)))
	}
	return msgs
}

func validateCookieSecret(secret string, secretFile string) []string {
	if secret == "" && secretFile == "" {
		return []string{"missing setting: cookie-secret or cookie-secret-file"}
	}
	if secret == "" && secretFile != "" {
		fileData, err := os.ReadFile(secretFile)
		if err != nil {
			return []string{"could not read cookie secret file: " + secretFile}
		}
		// Validate the file content as a secret
		secretBytes := encryption.SecretBytes(string(fileData))
		switch len(secretBytes) {
		case 16, 24, 32:
			// Valid secret size found
			return []string{}
		}
		// Invalid secret size found, return a message
		return []string{fmt.Sprintf(
			"cookie_secret from file must be 16, 24, or 32 bytes to create an AES cipher, but is %d bytes",
			len(secretBytes)),
		}
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
