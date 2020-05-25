package cookie

import (
	"fmt"
	mathrand "math/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cookie SessionStore")
}

var _ = Describe("Cookie SessionStore Tests", func() {
	tests.RunSessionStoreTests(
		func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			// Set the connection URL
			opts.Type = options.CookieSessionStoreType
			return NewCookieSessionStore(opts, cookieOpts)
		}, nil)
})

func Test_copyCookie(t *testing.T) {
	expire, _ := time.Parse(time.RFC3339, "2020-03-17T00:00:00Z")
	c := &http.Cookie{
		Name:       "name",
		Value:      "value",
		Path:       "/path",
		Domain:     "x.y.z",
		Expires:    expire,
		RawExpires: "rawExpire",
		MaxAge:     1,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "raw",
		Unparsed:   []string{"unparsed"},
		SameSite:   http.SameSiteLaxMode,
	}

	got := copyCookie(c)
	assert.Equal(t, c, got)
}

func Test_splitCookie(t *testing.T) {
	testCases := map[string]*http.Cookie{
		"Short cookie name": {
			Name:  "short",
			Value: strings.Repeat("v", 10000),
		},
		"Long cookie name": {
			Name:  strings.Repeat("n", 251),
			Value: strings.Repeat("a", 10000),
		},
		"Max cookie name": {
			Name:  strings.Repeat("n", 256),
			Value: strings.Repeat("a", 10000),
		},
		"Suffix overflow cookie name": {
			Name:  strings.Repeat("n", 255),
			Value: strings.Repeat("a", 10000),
		},
		"Double digit suffix cookie name overflow": {
			Name:  strings.Repeat("n", 253),
			Value: strings.Repeat("a", 50000),
		},
		"With short name and attributes": {
			Name:     "short",
			Value:    strings.Repeat("v", 10000),
			Path:     "/path",
			Domain:   "x.y.z",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
		"With max length name and attributes": {
			Name:     strings.Repeat("n", 256),
			Value:    strings.Repeat("v", 10000),
			Path:     "/path",
			Domain:   "x.y.z",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			splitCookies := splitCookie(tc)
			for i, cookie := range splitCookies {
				if i < len(splitCookies)-1 {
					assert.Equal(t, 4000, len(cookie.String()))
				} else {
					assert.GreaterOrEqual(t, 4000, len(cookie.String()))
				}
			}
		})
	}
}

func Test_splitCookieName(t *testing.T) {
	testCases := map[string]struct {
		Name   string
		Count  int
		Output string
	}{
		"Standard length": {
			Name:   "IAmSoNormal",
			Count:  2,
			Output: "IAmSoNormal_2",
		},
		"Max length": {
			Name:   strings.Repeat("n", 256),
			Count:  1,
			Output: fmt.Sprintf("%s_%d", strings.Repeat("n", 254), 1),
		},
		"Large count overflow": {
			Name:   strings.Repeat("n", 253),
			Count:  1000,
			Output: fmt.Sprintf("%s_%d", strings.Repeat("n", 251), 1000),
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			splitName := splitCookieName(tc.Name, tc.Count)
			assert.Equal(t, tc.Output, splitName)
		})
	}
}

func Test_splitCookie_joinCookies(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	v := make([]byte, 251)
	for i := range v {
		v[i] = charset[mathrand.Intn(len(charset))]
	}
	value := strings.Repeat(string(v), 1000)

	for _, nameSize := range []int{1, 10, 50, 100, 200, 254} {
		t.Run(fmt.Sprintf("%d length cookie name", nameSize), func(t *testing.T) {
			cookie := &http.Cookie{
				Name:  strings.Repeat("n", nameSize),
				Value: value,
			}
			splitCookies := splitCookie(cookie)
			joinedCookie, err := joinCookies(splitCookies)
			assert.NoError(t, err)
			assert.Equal(t, *cookie, *joinedCookie)
		})
	}
}
