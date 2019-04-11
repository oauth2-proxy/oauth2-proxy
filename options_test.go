package main

import (
	"crypto"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		"missing setting: cookie-secret",
		"missing setting: client-id",
		"missing setting: client-secret"})
	assert.Equal(t, expected, err.Error())
}

func TestGoogleGroupOptions(t *testing.T) {
	o := testOptions()
	o.GoogleGroups = []string{"googlegroup"}
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: google-admin-email",
		"missing setting: google-service-account-json"})
	assert.Equal(t, expected, err.Error())
}

func TestGoogleGroupInvalidFile(t *testing.T) {
	o := testOptions()
	o.GoogleGroups = []string{"test_group"}
	o.GoogleAdminEmail = "admin@example.com"
	o.GoogleServiceAccountJSON = "file_doesnt_exist.json"
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"invalid Google credentials file: file_doesnt_exist.json",
	})
	assert.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions()
	o.RedirectURL = "https://myhost.com/oauth2/callback"
	assert.Equal(t, nil, o.Validate())
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	assert.Equal(t, expected, o.redirectURL)
}

func TestProxyURLs(t *testing.T) {
	o := testOptions()
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8081")
	assert.Equal(t, nil, o.Validate())
	expected := []*url.URL{
		{Scheme: "http", Host: "127.0.0.1:8080", Path: "/"},
		// note the '/' was added
		{Scheme: "http", Host: "127.0.0.1:8081", Path: "/"},
	}
	assert.Equal(t, expected, o.proxyURLs)
}

func TestProxyURLsError(t *testing.T) {
	o := testOptions()
	o.Upstreams = append(o.Upstreams, "127.0.0.1:8081")
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"error parsing upstream: parse 127.0.0.1:8081: " +
			"first path segment in URL cannot contain colon"})
	assert.Equal(t, expected, err.Error())
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

	o.SkipAuthRegex = []string{"foobaz", "barquux)"}
	err = o.Validate()
	assert.NotEqual(t, nil, err)

	expected = errorMsg([]string{
		"error compiling regex=\"barquux)\" error parsing regexp: " +
			"unexpected ): `barquux)`"})
	assert.Equal(t, expected, err.Error())
}

func TestDefaultProviderApiSettings(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())
	p := o.provider.Data()
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth?access_type=offline",
		p.LoginURL.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/token",
		p.RedeemURL.String())
	assert.Equal(t, "", p.ProfileURL.String())
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

	o.CookieSecret = "0123456789abcdefabcd"
	o.CookieRefresh = o.CookieExpire
	assert.NotEqual(t, nil, o.Validate())

	o.CookieRefresh -= time.Duration(1)
	assert.Equal(t, nil, o.Validate())
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	assert.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
	assert.Equal(t, nil, o.Validate())

	// 24 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "Kp33Gj-GQmYtz4zZUyUDdqQKx5_Hgkv3"
	assert.Equal(t, nil, o.Validate())

	// 16 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "LFEqZYvYUwKwzn0tEuTpLA=="
	assert.Equal(t, nil, o.Validate())

	// 16 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "LFEqZYvYUwKwzn0tEuTpLA"
	assert.Equal(t, nil, o.Validate())
}

func TestValidateSignatureKey(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "sha1:secret"
	assert.Equal(t, nil, o.Validate())
	assert.Equal(t, o.signatureData.hash, crypto.SHA1)
	assert.Equal(t, o.signatureData.key, "secret")
}

func TestValidateSignatureKeyInvalidSpec(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "invalid spec"
	err := o.Validate()
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		"  invalid signature hash:key spec: "+o.SignatureKey)
}

func TestValidateSignatureKeyUnsupportedAlgorithm(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "unsupported:default secret"
	err := o.Validate()
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		"  unsupported signature hash algorithm: "+o.SignatureKey)
}

func TestValidateCookie(t *testing.T) {
	o := testOptions()
	o.CookieName = "_valid_cookie_name"
	assert.Equal(t, nil, o.Validate())
}

func TestValidateCookieBadName(t *testing.T) {
	o := testOptions()
	o.CookieName = "_bad_cookie_name{}"
	err := o.Validate()
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		fmt.Sprintf("  invalid cookie name: %q", o.CookieName))
}

func TestSkipOIDCDiscovery(t *testing.T) {
	o := testOptions()
	o.Provider = "oidc"
	o.OIDCIssuerURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/"
	o.SkipOIDCDiscovery = true

	err := o.Validate()
	assert.Equal(t, "Invalid configuration:\n"+
		fmt.Sprintf("  missing setting: login-url\n  missing setting: redeem-url\n  missing setting: oidc-jwks-url"), err.Error())

	o.LoginURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=b2c_1_sign_in"
	o.RedeemURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/token?p=b2c_1_sign_in"
	o.OIDCJwksURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/discovery/v2.0/keys"

	assert.Equal(t, nil, o.Validate())
}

func TestGCPHealthcheck(t *testing.T) {
	o := testOptions()
	o.GCPHealthChecks = true
	assert.Equal(t, nil, o.Validate())
}
