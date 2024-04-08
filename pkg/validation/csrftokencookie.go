package validation

import (
	"fmt"
	"sort"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func validateCSRFTokenOptions(o options.CSRFToken) []string {
	var msgs []string
	msgs = append(msgs, validateCSRFTokenCookie(o)...)

	return msgs
}

func validateCSRFTokenCookie(o options.CSRFToken) []string {
	var msgs []string

	// If cookie name is empty string then return since cookie is disabled
	if o.CookieName == "" {
		return msgs
	}

	msgs = append(msgs, validateCookieName(o.CookieName)...)

	switch o.CookieSameSite {
	case "", "none", "lax", "strict":
	default:
		msgs = append(msgs, fmt.Sprintf("csrftoken_cookie_samesite (%q) must be one of ['', 'lax', 'strict', 'none']", o.CookieSameSite))
	}

	// Sort cookie domains by length, so that we try longer (and more specific) domains first
	sort.Slice(o.CookieDomains, func(i, j int) bool {
		return len(o.CookieDomains[i]) > len(o.CookieDomains[j])
	})

	return msgs
}
