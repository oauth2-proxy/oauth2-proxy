package validation

import (
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/gomega"
)

func TestValidateCookie(t *testing.T) {
	validName := "_oauth2_proxy"
	invalidName := "_oauth2;proxy" // Separater character not allowed
	validSecret := "secretthirtytwobytes+abcdefghijk"
	invalidSecret := "abcdef"                                          // 6 bytes is not a valid size
	validBase64Secret := "c2VjcmV0dGhpcnR5dHdvYnl0ZXMrYWJjZGVmZ2hpams" // Base64 encoding of "secretthirtytwobytes+abcdefghijk"
	invalidBase64Secret := "YWJjZGVmCg"                                // Base64 encoding of "abcdef"
	emptyDomains := []string{}
	domains := []string{
		"a.localhost",
		"ba.localhost",
		"ca.localhost",
		"cba.localhost",
		"a.cba.localhost",
	}

	invalidNameMsg := "invalid cookie name: \"_oauth2;proxy\""
	missingSecretMsg := "missing setting: cookie-secret"
	invalidSecretMsg := "cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is 6 bytes"
	invalidBase64SecretMsg := "cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is 10 bytes"
	refreshLongerThanExpireMsg := "cookie_refresh (\"1h0m0s\") must be less than cookie_expire (\"15m0s\")"
	invalidSameSiteMsg := "cookie_samesite (\"invalid\") must be one of ['', 'lax', 'strict', 'none']"

	testCases := []struct {
		name       string
		cookie     options.CookieOptions
		errStrings []string
	}{
		{
			name: "with valid configuration",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validSecret,
				Domains:  domains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{},
		},
		{
			name: "with no cookie secret",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   "",
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{
				missingSecretMsg,
			},
		},
		{
			name: "with an invalid cookie secret",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   invalidSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{
				invalidSecretMsg,
			},
		},
		{
			name: "with a valid Base64 secret",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validBase64Secret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{},
		},
		{
			name: "with an invalid Base64 secret",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   invalidBase64Secret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{
				invalidBase64SecretMsg,
			},
		},
		{
			name: "with an invalid name",
			cookie: options.CookieOptions{
				Name:     invalidName,
				Secret:   validSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{
				invalidNameMsg,
			},
		},
		{
			name: "with refresh longer than expire",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   15 * time.Minute,
				Refresh:  time.Hour,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{
				refreshLongerThanExpireMsg,
			},
		},
		{
			name: "with samesite \"none\"",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "none",
			},
			errStrings: []string{},
		},
		{
			name: "with samesite \"lax\"",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "none",
			},
			errStrings: []string{},
		},
		{
			name: "with samesite \"strict\"",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "none",
			},
			errStrings: []string{},
		},
		{
			name: "with samesite \"invalid\"",
			cookie: options.CookieOptions{
				Name:     validName,
				Secret:   validSecret,
				Domains:  emptyDomains,
				Path:     "",
				Expire:   time.Hour,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "invalid",
			},
			errStrings: []string{
				invalidSameSiteMsg,
			},
		},
		{
			name: "with a combination of configuration errors",
			cookie: options.CookieOptions{
				Name:     invalidName,
				Secret:   invalidSecret,
				Domains:  domains,
				Path:     "",
				Expire:   15 * time.Minute,
				Refresh:  time.Hour,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "invalid",
			},
			errStrings: []string{
				invalidNameMsg,
				invalidSecretMsg,
				refreshLongerThanExpireMsg,
				invalidSameSiteMsg,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errStrings := validateCookieOptions(tc.cookie)
			g := NewWithT(t)

			g.Expect(errStrings).To(ConsistOf(tc.errStrings))
			// Check domains were sorted to the right lengths
			for i := 0; i < len(tc.cookie.Domains)-1; i++ {
				g.Expect(len(tc.cookie.Domains[i])).To(BeNumerically(">=", len(tc.cookie.Domains[i+1])))
			}
		})
	}
}
