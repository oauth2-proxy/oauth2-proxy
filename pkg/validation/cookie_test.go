package validation

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	. "github.com/onsi/gomega"
)

func TestValidateCookie(t *testing.T) {
	alphabet := "abcdefghijklmnopqrstuvwxyz"

	validName := "_oauth2_proxy"
	invalidName := "_oauth2;proxy" // Separater character not allowed
	// 10 times the alphabet should be longer than 256 characters
	longName := strings.Repeat(alphabet, 10)
	validSecret := &options.SecretSource{
		Value: []byte("secretthirtytwobytes+abcdefghijk"),
	}
	// 6 bytes is not a valid size
	invalidSecret := &options.SecretSource{
		Value: []byte("abcdef"),
	}

	// Base64 encoding of "secretthirtytwobytes+abcdefghijk"
	validBase64Secret := options.SecretSource{
		Value: []byte("c2VjcmV0dGhpcnR5dHdvYnl0ZXMrYWJjZGVmZ2hpams"),
	}
	// Base64 encoding of "abcdef"
	invalidBase64Secret := options.SecretSource{
		Value: []byte("YWJjZGVmCg"),
	}
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
	_, err = tmpfile.Write(validSecret.Value)
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
	invalidSameSiteMsg := "cookie_samesite (\"invalid\") must be one of ['', 'Lax', 'Strict', 'None']"

	testCases := []struct {
		name       string
		cookie     options.Cookie
		refresh    time.Duration
		errStrings []string
	}{
		{
			name: "with valid configuration",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       validSecret,
				Domains:      domains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh:    15 * time.Minute,
			errStrings: []string{},
		},
		{
			name: "with no cookie secret",
			cookie: options.Cookie{
				Name: validName,
				Secret: &options.SecretSource{
					Value:    nil,
					FromFile: "",
				},
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh: 15 * time.Minute,
			errStrings: []string{
				missingSecretMsg,
			},
		},
		{
			name: "with an invalid cookie secret",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       invalidSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh: 15 * time.Minute,
			errStrings: []string{
				invalidSecretMsg,
			},
		},
		{
			name: "with a valid Base64 secret",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       &validBase64Secret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh:    15 * time.Minute,
			errStrings: []string{},
		},
		{
			name: "with an invalid Base64 secret",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       &invalidBase64Secret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh: 15 * time.Minute,
			errStrings: []string{
				invalidBase64SecretMsg,
			},
		},
		{
			name: "with an invalid name",
			cookie: options.Cookie{
				Name:         invalidName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh: 15 * time.Minute,
			errStrings: []string{
				invalidNameMsg,
			},
		},
		{
			name: "with a name that is too long",
			cookie: options.Cookie{
				Name:         longName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh: 15 * time.Minute,
			errStrings: []string{
				longNameMsg,
			},
		},
		{
			name: "with refresh longer than expire",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       15 * time.Minute,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh: time.Hour,
			errStrings: []string{
				refreshLongerThanExpireMsg,
			},
		},
		{
			name: "with samesite \"none\"",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     options.SameSiteNone,
			},
			refresh:    15 * time.Minute,
			errStrings: []string{},
		},
		{
			name: "with samesite \"lax\"",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     options.SameSiteLax,
			},
			refresh:    15 * time.Minute,
			errStrings: []string{},
		},
		{
			name: "with samesite \"strict\"",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     options.SameSiteStrict,
			},
			refresh:    15 * time.Minute,
			errStrings: []string{},
		},
		{
			name: "with samesite \"invalid\"",
			cookie: options.Cookie{
				Name:         validName,
				Secret:       validSecret,
				Domains:      emptyDomains,
				Path:         "",
				Expire:       time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "invalid",
			},
			refresh: 15 * time.Minute,
			errStrings: []string{
				invalidSameSiteMsg,
			},
		},
		{
			name: "with a combination of configuration errors",
			cookie: options.Cookie{
				Name:         invalidName,
				Secret:       invalidSecret,
				Domains:      domains,
				Path:         "",
				Expire:       15 * time.Minute,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "invalid",
			},
			refresh: time.Hour,
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
				Name:         validName,
				Secret:       validSecret,
				Domains:      domains,
				Path:         "",
				Expire:       0,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessAllowed,
				SameSite:     "",
			},
			refresh:    15 * time.Minute,
			errStrings: []string{},
		},
		{
			name: "with valid secret file",
			cookie: options.Cookie{
				Name: validName,
				Secret: &options.SecretSource{
					FromFile: tmpfile.Name(),
				},
				Domains:      domains,
				Path:         "",
				Expire:       24 * time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessDenied,
				SameSite:     "",
			},
			refresh:    0,
			errStrings: []string{},
		},
		{
			name: "with nonexistent secret file",
			cookie: options.Cookie{
				Name: validName,
				Secret: &options.SecretSource{
					FromFile: "/nonexistent/file.txt",
				},
				Domains:      domains,
				Path:         "",
				Expire:       24 * time.Hour,
				Insecure:     ptr.To(false),
				ScriptAccess: options.ScriptAccessDenied,
				SameSite:     "",
			},
			refresh:    0,
			errStrings: []string{"error retrieving cookie secret: error reading secret from file \"/nonexistent/file.txt\": open /nonexistent/file.txt: no such file or directory"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errStrings := validateCookie(tc.cookie, tc.refresh)
			g := NewWithT(t)

			g.Expect(errStrings).To(ConsistOf(tc.errStrings))
			// Check domains were sorted to the right lengths
			for i := 0; i < len(tc.cookie.Domains)-1; i++ {
				g.Expect(len(tc.cookie.Domains[i])).To(BeNumerically(">=", len(tc.cookie.Domains[i+1])))
			}
		})
	}
}
