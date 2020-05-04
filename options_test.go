package main

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	cookieSecret = "foobar"
	clientID     = "bazquux"
	clientSecret = "xyzzyplugh"
)

func testOptions() *Options {
	o := NewOptions()
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8080/")
	o.Cookie.Secret = cookieSecret
	o.ClientID = clientID
	o.ClientSecret = clientSecret
	o.EmailDomains = []string{"*"}
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "invalid configuration:")
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
		"missing setting: client-secret or client-secret-file"})
	assert.Equal(t, expected, err.Error())
}

func TestClientSecretFileOptionFails(t *testing.T) {
	o := NewOptions()
	o.Cookie.Secret = cookieSecret
	o.ClientID = clientID
	o.ClientSecretFile = clientSecret
	o.EmailDomains = []string{"*"}
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	p := o.provider.Data()
	assert.Equal(t, clientSecret, p.ClientSecretFile)
	assert.Equal(t, "", p.ClientSecret)

	s, err := p.GetClientSecret()
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", s)
}

func TestClientSecretFileOption(t *testing.T) {
	var err error
	f, err := ioutil.TempFile("", "client_secret_temp_file_")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.WriteString("testcase")
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	clientSecretFileName := f.Name()
	defer os.Remove(clientSecretFileName)

	o := NewOptions()
	o.Cookie.Secret = cookieSecret
	o.ClientID = clientID
	o.ClientSecretFile = clientSecretFileName
	o.EmailDomains = []string{"*"}
	err = o.Validate()
	assert.Equal(t, nil, err)

	p := o.provider.Data()
	assert.Equal(t, clientSecretFileName, p.ClientSecretFile)
	assert.Equal(t, "", p.ClientSecret)

	s, err := p.GetClientSecret()
	assert.Equal(t, nil, err)
	assert.Equal(t, "testcase", s)
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
	assert.Contains(t, err.Error(), "error parsing upstream")
}

func TestCompiledRegex(t *testing.T) {
	o := testOptions()
	regexps := []string{"/foo/.*", "/ba[rz]/quux"}
	o.SkipAuthRegex = regexps
	assert.Equal(t, nil, o.Validate())
	actual := make([]string, 0)
	for _, regex := range o.compiledRegex {
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
	o.Cookie.Secret = "cookie of invalid length-"
	assert.NotEqual(t, nil, o.Validate())

	o.PassAccessToken = false
	o.Cookie.Refresh = time.Duration(24) * time.Hour
	assert.NotEqual(t, nil, o.Validate())

	o.Cookie.Secret = "16 bytes AES-128"
	assert.Equal(t, nil, o.Validate())

	o.Cookie.Secret = "24 byte secret AES-192--"
	assert.Equal(t, nil, o.Validate())

	o.Cookie.Secret = "32 byte secret for AES-256------"
	assert.Equal(t, nil, o.Validate())
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())

	o.Cookie.Secret = "0123456789abcdefabcd"
	o.Cookie.Refresh = o.Cookie.Expire
	assert.NotEqual(t, nil, o.Validate())

	o.Cookie.Refresh -= time.Duration(1)
	assert.Equal(t, nil, o.Validate())
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	assert.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.Cookie.Secret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
	assert.Equal(t, nil, o.Validate())

	// 24 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "Kp33Gj-GQmYtz4zZUyUDdqQKx5_Hgkv3"
	assert.Equal(t, nil, o.Validate())

	// 16 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "LFEqZYvYUwKwzn0tEuTpLA=="
	assert.Equal(t, nil, o.Validate())

	// 16 byte, base64 (urlsafe) encoded key, w/o padding
	o.Cookie.Secret = "LFEqZYvYUwKwzn0tEuTpLA"
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
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		"  invalid signature hash:key spec: "+o.SignatureKey)
}

func TestValidateSignatureKeyUnsupportedAlgorithm(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "unsupported:default secret"
	err := o.Validate()
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		"  unsupported signature hash algorithm: "+o.SignatureKey)
}

func TestValidateCookie(t *testing.T) {
	o := testOptions()
	o.Cookie.Name = "_valid_cookie_name"
	assert.Equal(t, nil, o.Validate())
}

func TestValidateCookieBadName(t *testing.T) {
	o := testOptions()
	o.Cookie.Name = "_bad_cookie_name{}"
	err := o.Validate()
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		fmt.Sprintf("  invalid cookie name: %q", o.Cookie.Name))
}

func TestSkipOIDCDiscovery(t *testing.T) {
	o := testOptions()
	o.Provider = "oidc"
	o.OIDCIssuerURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/"
	o.SkipOIDCDiscovery = true

	err := o.Validate()
	assert.Equal(t, "invalid configuration:\n"+
		"  missing setting: login-url\n  missing setting: redeem-url\n  missing setting: oidc-jwks-url", err.Error())

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
