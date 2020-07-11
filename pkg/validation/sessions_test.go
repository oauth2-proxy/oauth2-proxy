package validation

import (
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/gomega"
)

func Test_validateSessionCookieMinimal(t *testing.T) {
	const (
		passAuthorizationMsg = "pass_authorization_header requires oauth tokens in sessions. session_cookie_minimal cannot be set"
		setAuthorizationMsg  = "set_authorization_header requires oauth tokens in sessions. session_cookie_minimal cannot be set"
		passAccessTokenMsg   = "pass_access_token requires oauth tokens in sessions. session_cookie_minimal cannot be set"
		cookieRefreshMsg     = "cookie_refresh > 0 requires oauth tokens in sessions. session_cookie_minimal cannot be set"
	)

	testCases := map[string]struct {
		opts       *options.Options
		errStrings []string
	}{
		"No minimal cookie session": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: false,
					},
				},
			},
			errStrings: []string{},
		},
		"No minimal cookie session & passAuthorization": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: false,
					},
				},
				PassAuthorization: true,
			},
			errStrings: []string{},
		},
		"Minimal cookie session no conflicts": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
			},
			errStrings: []string{},
		},
		"PassAuthorization conflict": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				PassAuthorization: true,
			},
			errStrings: []string{passAuthorizationMsg},
		},
		"SetAuthorization conflict": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				SetAuthorization: true,
			},
			errStrings: []string{setAuthorizationMsg},
		},
		"PassAccessToken conflict": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				PassAccessToken: true,
			},
			errStrings: []string{passAccessTokenMsg},
		},
		"CookieRefresh conflict": {
			opts: &options.Options{
				Cookie: options.Cookie{
					Refresh: time.Hour,
				},
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
			},
			errStrings: []string{cookieRefreshMsg},
		},
		"Multiple conflicts": {
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				PassAuthorization: true,
				PassAccessToken:   true,
			},
			errStrings: []string{passAuthorizationMsg, passAccessTokenMsg},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			errStrings := validateSessionCookieMinimal(tc.opts)
			g := NewWithT(t)
			g.Expect(errStrings).To(ConsistOf(tc.errStrings))
		})
	}
}
