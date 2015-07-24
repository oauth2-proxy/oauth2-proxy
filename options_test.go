package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bmizerany/assert"
)

func testOptions() *Options {
	o := NewOptions()
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8080/")
	o.CookieSecret = "foobar"
	o.ClientID = "bazquux"
	o.ClientSecret = "xyzzyplugh"
	o.EmailDomains = []string{"*"}
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o := NewOptions()
	o.EmailDomains = []string{"*"}
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: upstream",
		"missing setting: cookie-secret",
		"missing setting: client-id",
		"missing setting: client-secret"})
	assert.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectUrl(t *testing.T) {
	o := testOptions()
	o.RedirectUrl = "https://myhost.com/oauth2/callback"
	assert.Equal(t, nil, o.Validate())
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	assert.Equal(t, expected, o.redirectUrl)
}

func TestProxyUrls(t *testing.T) {
	o := testOptions()
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8081")
	assert.Equal(t, nil, o.Validate())
	expected := []*url.URL{
		&url.URL{Scheme: "http", Host: "127.0.0.1:8080", Path: "/"},
		// note the '/' was added
		&url.URL{Scheme: "http", Host: "127.0.0.1:8081", Path: "/"},
	}
	assert.Equal(t, expected, o.proxyUrls)
}

func TestCompiledRegex(t *testing.T) {
	o := testOptions()
	regexps := []string{"/foo/.*", "/ba[rz]/quux"}
	o.SkipAuthRegex = regexps
	assert.Equal(t, nil, o.Validate())
	actual := make([]string, 0)
	for _, regex := range o.CompiledRegex {
		actual = append(actual, regex.String())
	}
	assert.Equal(t, regexps, actual)
}

func TestCompiledRegexError(t *testing.T) {
	o := testOptions()
	o.SkipAuthRegex = []string{"(foobaz", "barquux)"}
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"error compiling regex=\"(foobaz\" error parsing regexp: " +
			"missing closing ): `(foobaz`",
		"error compiling regex=\"barquux)\" error parsing regexp: " +
			"unexpected ): `barquux)`"})
	assert.Equal(t, expected, err.Error())
}

func TestDefaultProviderApiSettings(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())
	p := o.provider.Data()
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth?access_type=offline",
		p.LoginUrl.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/token",
		p.RedeemUrl.String())
	assert.Equal(t, "", p.ProfileUrl.String())
	assert.Equal(t, "profile email", p.Scope)
}

func TestPassAccessTokenRequiresSpecificCookieSecretLengths(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())

	assert.Equal(t, false, o.PassAccessToken)
	o.PassAccessToken = true
	o.CookieSecret = "cookie of invalid length-"
	assert.NotEqual(t, nil, o.Validate())

	o.PassAccessToken = false
	o.CookieRefresh = time.Duration(24) * time.Hour
	assert.NotEqual(t, nil, o.Validate())

	o.CookieSecret = "16 bytes AES-128"
	assert.Equal(t, nil, o.Validate())

	o.CookieSecret = "24 byte secret AES-192--"
	assert.Equal(t, nil, o.Validate())

	o.CookieSecret = "32 byte secret for AES-256------"
	assert.Equal(t, nil, o.Validate())
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())

	o.CookieSecret = "0123456789abcdef"
	o.CookieRefresh = o.CookieExpire
	assert.NotEqual(t, nil, o.Validate())

	o.CookieRefresh -= time.Duration(1)
	assert.Equal(t, nil, o.Validate())
}
