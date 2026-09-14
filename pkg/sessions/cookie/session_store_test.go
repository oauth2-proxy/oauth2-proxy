package cookie

import (
	"fmt"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

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
		Partitioned: true,
	}

	got := copyCookie(c)
	assert.Equal(t, c, got)
}

func TestPartitionedSessionCookieRoundTrip(t *testing.T) {
	cookieOpts := &options.Cookie{
		Name:        "_oauth2_proxy",
		Secret:      strings.Repeat("s", 32),
		Path:        "/",
		Expire:      time.Hour,
		Secure:      true,
		SameSite:    "none",
		Partitioned: true,
	}
	store, err := NewCookieSessionStore(&options.SessionOptions{}, cookieOpts)
	if !assert.NoError(t, err) {
		return
	}

	saveRequest := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	saveResponse := httptest.NewRecorder()
	session := &sessionsapi.SessionState{User: "user"}
	if !assert.NoError(t, store.Save(saveResponse, saveRequest, session)) {
		return
	}

	setCookieHeaders := saveResponse.Header().Values("Set-Cookie")
	if !assert.NotEmpty(t, setCookieHeaders) {
		return
	}
	for _, header := range setCookieHeaders {
		assert.Contains(t, header, "; Secure; SameSite=None; Partitioned")
		cookie, err := http.ParseSetCookie(header)
		if assert.NoError(t, err) {
			assert.True(t, cookie.Partitioned)
			assert.True(t, cookie.Secure)
			assert.Equal(t, http.SameSiteNoneMode, cookie.SameSite)
		}
	}

	loadRequest := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	for _, cookie := range saveResponse.Result().Cookies() {
		loadRequest.AddCookie(cookie)
	}
	loaded, err := store.Load(loadRequest)
	if assert.NoError(t, err) {
		assert.Equal(t, session.User, loaded.User)
	}

	clearResponse := httptest.NewRecorder()
	if !assert.NoError(t, store.Clear(clearResponse, loadRequest)) {
		return
	}
	for _, header := range clearResponse.Header().Values("Set-Cookie") {
		assert.Contains(t, header, "; Secure; SameSite=None; Partitioned")
		cookie, err := http.ParseSetCookie(header)
		if assert.NoError(t, err) {
			assert.Equal(t, -1, cookie.MaxAge)
			assert.True(t, cookie.Partitioned)
		}
	}
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
			Partitioned: true,
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
				assert.Equal(t, tc.Partitioned, cookie.Partitioned)
				if tc.Partitioned {
					assert.Contains(t, cookie.String(), "; Partitioned")
				}
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
			joinedCookie, err := joinCookies(splitCookies, cookie.Name)
			assert.NoError(t, err)
			assert.Equal(t, *cookie, *joinedCookie)
		})
	}
}

func Test_joinCookies_withUnderlineSuffix(t *testing.T) {
	testCases := map[string]struct {
		CookieName string
		SplitOrder []int
	}{
		"Ascending order split with \"_\" suffix": {
			CookieName: "_cookie_name_",
			SplitOrder: []int{0, 1, 2, 3, 4},
		},
		"Descending order split with \"_\" suffix": {
			CookieName: "_cookie_name_",
			SplitOrder: []int{4, 3, 2, 1, 0},
		},
		"Arbitrary order split with \"_\" suffix": {
			CookieName: "_cookie_name_",
			SplitOrder: []int{3, 1, 2, 0, 4},
		},
		"Arbitrary order split with \"_0\" suffix": {
			CookieName: "_cookie_name_0",
			SplitOrder: []int{1, 3, 0, 2, 4},
		},
		"Arbitrary order split with \"_1\" suffix": {
			CookieName: "_cookie_name_1",
			SplitOrder: []int{4, 1, 3, 0, 2},
		},
		"Arbitrary order split with \"__\" suffix": {
			CookieName: "_cookie_name__",
			SplitOrder: []int{1, 0, 4, 3, 2},
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			cookieName := testCase.CookieName
			var splitCookies []*http.Cookie
			for _, splitSuffix := range testCase.SplitOrder {
				cookie := &http.Cookie{
					Name:  splitCookieName(cookieName, splitSuffix),
					Value: strings.Repeat("v", 1000),
				}
				splitCookies = append(splitCookies, cookie)
			}
			joinedCookie, err := joinCookies(splitCookies, cookieName)
			assert.NoError(t, err)
			assert.Equal(t, cookieName, joinedCookie.Name)
		})
	}
}
