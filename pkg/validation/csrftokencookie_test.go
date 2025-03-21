package validation

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/gomega"
)

func TestValidateCSRFTokenCookie(t *testing.T) {
	alphabet := "abcdefghijklmnopqrstuvwxyz"

	validName := "_oauth2_proxy_csrftoken"
	invalidName := "_oauth2;proxy_csrftoken" // Separater character not allowed
	// 10 times the alphabet should be longer than 256 characters
	longName := strings.Repeat(alphabet, 10)
	emptyDomains := []string{}
	domains := []string{
		"a.localhost",
		"ba.localhost",
		"ca.localhost",
		"cba.localhost",
		"a.cba.localhost",
	}

	invalidNameMsg := fmt.Sprintf("invalid cookie name: \"%s\"", invalidName)
	longNameMsg := "cookie name should be under 256 characters: cookie name is 260 characters"
	invalidSameSiteMsg := "csrftoken_cookie_samesite (\"invalid\") must be one of ['', 'lax', 'strict', 'none']"

	testCases := []struct {
		name       string
		cookie     options.CSRFToken
		errStrings []string
	}{
		{
			name: "with valid configuration",
			cookie: options.CSRFToken{
				CookieName:     validName,
				CookieDomains:  domains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "",
			},
			errStrings: []string{},
		},
		{
			name: "with an invalid name",
			cookie: options.CSRFToken{
				CookieName:     invalidName,
				CookieDomains:  emptyDomains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "",
			},
			errStrings: []string{
				invalidNameMsg,
			},
		},
		{
			name: "with a name that is too long",
			cookie: options.CSRFToken{
				CookieName:     longName,
				CookieDomains:  emptyDomains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "",
			},
			errStrings: []string{
				longNameMsg,
			},
		},
		{
			name: "with samesite \"none\"",
			cookie: options.CSRFToken{
				CookieName:     validName,
				CookieDomains:  emptyDomains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "none",
			},
			errStrings: []string{},
		},
		{
			name: "with samesite \"lax\"",
			cookie: options.CSRFToken{
				CookieName:     validName,
				CookieDomains:  emptyDomains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "lax",
			},
			errStrings: []string{},
		},
		{
			name: "with samesite \"strict\"",
			cookie: options.CSRFToken{
				CookieName:     validName,
				CookieDomains:  emptyDomains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "strict",
			},
			errStrings: []string{},
		},
		{
			name: "with samesite \"invalid\"",
			cookie: options.CSRFToken{
				CookieName:     validName,
				CookieDomains:  emptyDomains,
				CookiePath:     "",
				CookieExpire:   time.Hour,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "invalid",
			},
			errStrings: []string{
				invalidSameSiteMsg,
			},
		},
		{
			name: "with a combination of configuration errors",
			cookie: options.CSRFToken{
				CookieName:     invalidName,
				CookieDomains:  domains,
				CookiePath:     "",
				CookieExpire:   15 * time.Minute,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "invalid",
			},
			errStrings: []string{
				invalidNameMsg,
				invalidSameSiteMsg,
			},
		},
		{
			name: "with session cookie configuration",
			cookie: options.CSRFToken{
				CookieName:     validName,
				CookieDomains:  domains,
				CookiePath:     "",
				CookieExpire:   0,
				CookieSecure:   true,
				CookieHTTPOnly: false,
				CookieSameSite: "",
			},
			errStrings: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errStrings := validateCSRFTokenCookie(tc.cookie)
			g := NewWithT(t)

			g.Expect(errStrings).To(ConsistOf(tc.errStrings))
			// Check domains were sorted to the right lengths
			for i := 0; i < len(tc.cookie.CookieDomains)-1; i++ {
				g.Expect(len(tc.cookie.CookieDomains[i])).To(BeNumerically(">=", len(tc.cookie.CookieDomains[i+1])))
			}
		})
	}
}
