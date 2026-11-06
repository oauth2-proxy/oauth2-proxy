package validation

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/gomega"
)

func TestValidateCookie(t *testing.T) {
	alphabet := "abcdefghijklmnopqrstuvwxyz"

	validName := "_oauth2_proxy"
	invalidName := "_oauth2;proxy" // Separater character not allowed
	// 10 times the alphabet should be longer than 256 characters
	longName := strings.Repeat(alphabet, 10)
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

	// Create a temporary file for the valid secret file test
	tmpfile, err := os.CreateTemp("", "cookie-secret-test")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write a valid 32-byte secret to the file
	_, err = tmpfile.Write([]byte(validSecret))
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	tmpfile.Close()

	invalidNameMsg := "invalid cookie name: \"_oauth2;proxy\""
	longNameMsg := "cookie name should be under 256 characters: cookie name is 260 characters"
	missingSecretMsg := "missing setting: cookie-secret or cookie-secret-file"
	invalidSecretMsg := "cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is 6 bytes"
	invalidBase64SecretMsg := "cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is 10 bytes"
	refreshLongerThanExpireMsg := "cookie_refresh (\"1h0m0s\") must be less than cookie_expire (\"15m0s\")"
	invalidSameSiteMsg := "cookie_samesite (\"invalid\") must be one of ['', 'lax', 'strict', 'none']"

	testCases := []struct {
		name       string
		cookie     options.Cookie
		errStrings []string
	}{
		{
			name: "with valid configuration",
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			name: "with a name that is too long",
			cookie: options.Cookie{
				Name:     longName,
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
				longNameMsg,
			},
		},
		{
			name: "with refresh longer than expire",
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
			cookie: options.Cookie{
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
		{
			name: "with session cookie configuration",
			cookie: options.Cookie{
				Name:     validName,
				Secret:   validSecret,
				Domains:  domains,
				Path:     "",
				Expire:   0,
				Refresh:  15 * time.Minute,
				Secure:   true,
				HTTPOnly: false,
				SameSite: "",
			},
			errStrings: []string{},
		},
		{
			name: "with valid secret file",
			cookie: options.Cookie{
				Name:       validName,
				Secret:     "",
				SecretFile: tmpfile.Name(),
				Domains:    domains,
				Path:       "",
				Expire:     24 * time.Hour,
				Refresh:    0,
				Secure:     true,
				HTTPOnly:   true,
				SameSite:   "",
			},
			errStrings: []string{},
		},
		{
			name: "with nonexistent secret file",
			cookie: options.Cookie{
				Name:       validName,
				Secret:     "",
				SecretFile: "/nonexistent/file.txt",
				Domains:    domains,
				Path:       "",
				Expire:     24 * time.Hour,
				Refresh:    0,
				Secure:     true,
				HTTPOnly:   true,
				SameSite:   "",
			},
			errStrings: []string{"could not read cookie secret file: /nonexistent/file.txt"},
		},
		{
			name: "with valid __Host- prefixed name",
			cookie: options.Cookie{
				Name:    "__Host-oauth2_proxy",
				Secret:  validSecret,
				Domains: emptyDomains,
				Path:    "/",
				Secure:  true,
			},
			errStrings: []string{},
		},
		{
			name: "with __Host- prefixed name and invalid attributes",
			cookie: options.Cookie{
				Name:    "__Host-oauth2_proxy",
				Secret:  validSecret,
				Domains: domains,
				Path:    "/oauth2",
				Secure:  false,
			},
			errStrings: []string{
				"cookie_name (\"__Host-oauth2_proxy\") uses the __Host- prefix, which requires cookie_secure to be true",
				"cookie_name (\"__Host-oauth2_proxy\") uses the __Host- prefix, which does not allow cookie_domains to be set",
				"cookie_name (\"__Host-oauth2_proxy\") uses the __Host- prefix, which requires cookie_path to be \"/\"",
			},
		},
		{
			name: "with __Host-Http- prefixed name and cookie domains",
			cookie: options.Cookie{
				Name:     "__Host-Http-oauth2_proxy",
				Secret:   validSecret,
				Domains:  []string{".example.com"},
				Path:     "/",
				Secure:   true,
				HTTPOnly: true,
			},
			errStrings: []string{
				"cookie_name (\"__Host-Http-oauth2_proxy\") uses the __Host- prefix, which does not allow cookie_domains to be set",
			},
		},
		{
			name: "with lowercase __host- prefixed name and cookie domains",
			cookie: options.Cookie{
				Name:    "__host-oauth2_proxy",
				Secret:  validSecret,
				Domains: []string{".example.com"},
				Path:    "/",
				Secure:  true,
			},
			errStrings: []string{
				"cookie_name (\"__host-oauth2_proxy\") uses the __Host- prefix, which does not allow cookie_domains to be set",
			},
		},
		{
			name: "with valid __Secure- prefixed name",
			cookie: options.Cookie{
				Name:    "__Secure-oauth2_proxy",
				Secret:  validSecret,
				Domains: domains,
				Path:    "/oauth2",
				Secure:  true,
			},
			errStrings: []string{},
		},
		{
			name: "with __Secure- prefixed name and insecure cookie",
			cookie: options.Cookie{
				Name:    "__Secure-oauth2_proxy",
				Secret:  validSecret,
				Domains: emptyDomains,
				Path:    "/",
				Secure:  false,
			},
			errStrings: []string{
				"cookie_name (\"__Secure-oauth2_proxy\") uses the __Secure- prefix, which requires cookie_secure to be true",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errStrings := validateCookie(tc.cookie)
			g := NewWithT(t)

			g.Expect(errStrings).To(ConsistOf(tc.errStrings))
			// Check domains were sorted to the right lengths
			for i := 0; i < len(tc.cookie.Domains)-1; i++ {
				g.Expect(len(tc.cookie.Domains[i])).To(BeNumerically(">=", len(tc.cookie.Domains[i+1])))
			}
		})
	}
}
