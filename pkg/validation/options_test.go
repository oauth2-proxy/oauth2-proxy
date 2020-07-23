package validation

import (
	"crypto"
	"errors"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

const (
	cookieSecret = "secretthirtytwobytes+abcdefghijk"
	clientID     = "bazquux"
	clientSecret = "xyzzyplugh"
)

func testOptions() *options.Options {
	o := options.NewOptions()
	o.UpstreamServers = append(o.UpstreamServers, options.Upstream{
		ID:   "upstream",
		Path: "/",
		URI:  "http://127.0.0.1:8080/",
	})
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
	o := options.NewOptions()
	o.EmailDomains = []string{"*"}
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: cookie-secret",
		"missing setting: client-id",
		"missing setting: client-secret or client-secret-file"})
	assert.Equal(t, expected, err.Error())
}

func TestClientSecretFileOptionFails(t *testing.T) {
	o := options.NewOptions()
	o.Cookie.Secret = cookieSecret
	o.ClientID = clientID
	o.ClientSecretFile = clientSecret
	o.EmailDomains = []string{"*"}
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	p := o.GetProvider().Data()
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

	o := options.NewOptions()
	o.Cookie.Secret = cookieSecret
	o.ClientID = clientID
	o.ClientSecretFile = clientSecretFileName
	o.EmailDomains = []string{"*"}
	err = Validate(o)
	assert.Equal(t, nil, err)

	p := o.GetProvider().Data()
	assert.Equal(t, clientSecretFileName, p.ClientSecretFile)
	assert.Equal(t, "", p.ClientSecret)

	s, err := p.GetClientSecret()
	assert.Equal(t, nil, err)
	assert.Equal(t, "testcase", s)
}

func TestGoogleGroupOptions(t *testing.T) {
	o := testOptions()
	o.GoogleGroups = []string{"googlegroup"}
	err := Validate(o)
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
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"invalid Google credentials file: file_doesnt_exist.json",
	})
	assert.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions()
	o.RawRedirectURL = "https://myhost.com/oauth2/callback"
	assert.Equal(t, nil, Validate(o))
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	assert.Equal(t, expected, o.GetRedirectURL())
}

func TestCompiledRegex(t *testing.T) {
	o := testOptions()
	regexps := []string{"/foo/.*", "/ba[rz]/quux"}
	o.SkipAuthRegex = regexps
	assert.Equal(t, nil, Validate(o))
	actual := make([]string, 0)
	for _, regex := range o.GetCompiledRegex() {
		actual = append(actual, regex.String())
	}
	assert.Equal(t, regexps, actual)
}

func TestCompiledRegexError(t *testing.T) {
	o := testOptions()
	o.SkipAuthRegex = []string{"(foobaz", "barquux)"}
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"error compiling regex=\"(foobaz\" error parsing regexp: " +
			"missing closing ): `(foobaz`",
		"error compiling regex=\"barquux)\" error parsing regexp: " +
			"unexpected ): `barquux)`"})
	assert.Equal(t, expected, err.Error())

	o.SkipAuthRegex = []string{"foobaz", "barquux)"}
	err = Validate(o)
	assert.NotEqual(t, nil, err)

	expected = errorMsg([]string{
		"error compiling regex=\"barquux)\" error parsing regexp: " +
			"unexpected ): `barquux)`"})
	assert.Equal(t, expected, err.Error())
}

func TestDefaultProviderApiSettings(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))
	p := o.GetProvider().Data()
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth?access_type=offline",
		p.LoginURL.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/token",
		p.RedeemURL.String())
	assert.Equal(t, "", p.ProfileURL.String())
	assert.Equal(t, "profile email", p.Scope)
}

func TestPassAccessTokenRequiresSpecificCookieSecretLengths(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))

	assert.Equal(t, false, o.PassAccessToken)
	o.PassAccessToken = true
	o.Cookie.Secret = "cookie of invalid length-"
	assert.NotEqual(t, nil, Validate(o))

	o.PassAccessToken = false
	o.Cookie.Refresh = time.Duration(24) * time.Hour
	assert.NotEqual(t, nil, Validate(o))

	o.Cookie.Secret = "16 bytes AES-128"
	assert.Equal(t, nil, Validate(o))

	o.Cookie.Secret = "24 byte secret AES-192--"
	assert.Equal(t, nil, Validate(o))

	o.Cookie.Secret = "32 byte secret for AES-256------"
	assert.Equal(t, nil, Validate(o))
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))

	o.Cookie.Secret = "0123456789abcdef"
	o.Cookie.Refresh = o.Cookie.Expire
	assert.NotEqual(t, nil, Validate(o))

	o.Cookie.Refresh -= time.Duration(1)
	assert.Equal(t, nil, Validate(o))
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))

	// 32 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	assert.Equal(t, nil, Validate(o))

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.Cookie.Secret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
	assert.Equal(t, nil, Validate(o))

	// 24 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "Kp33Gj-GQmYtz4zZUyUDdqQKx5_Hgkv3"
	assert.Equal(t, nil, Validate(o))

	// 16 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "LFEqZYvYUwKwzn0tEuTpLA=="
	assert.Equal(t, nil, Validate(o))

	// 16 byte, base64 (urlsafe) encoded key, w/o padding
	o.Cookie.Secret = "LFEqZYvYUwKwzn0tEuTpLA"
	assert.Equal(t, nil, Validate(o))
}

func TestValidateSignatureKey(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "sha1:secret"
	assert.Equal(t, nil, Validate(o))
	assert.Equal(t, o.GetSignatureData().Hash, crypto.SHA1)
	assert.Equal(t, o.GetSignatureData().Key, "secret")
}

func TestValidateSignatureKeyInvalidSpec(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "invalid spec"
	err := Validate(o)
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		"  invalid signature hash:key spec: "+o.SignatureKey)
}

func TestValidateSignatureKeyUnsupportedAlgorithm(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "unsupported:default secret"
	err := Validate(o)
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		"  unsupported signature hash algorithm: "+o.SignatureKey)
}

func TestSkipOIDCDiscovery(t *testing.T) {
	o := testOptions()
	o.ProviderType = "oidc"
	o.OIDCIssuerURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/"
	o.SkipOIDCDiscovery = true

	err := Validate(o)
	assert.Equal(t, "invalid configuration:\n"+
		"  missing setting: login-url\n  missing setting: redeem-url\n  missing setting: oidc-jwks-url", err.Error())

	o.LoginURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=b2c_1_sign_in"
	o.RedeemURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/token?p=b2c_1_sign_in"
	o.OIDCJwksURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/discovery/v2.0/keys"

	assert.Equal(t, nil, Validate(o))
}

func TestGCPHealthcheck(t *testing.T) {
	o := testOptions()
	o.GCPHealthChecks = true
	assert.Equal(t, nil, Validate(o))
}

func TestRealClientIPHeader(t *testing.T) {
	// Ensure nil if ReverseProxy not set.
	o := testOptions()
	o.RealClientIPHeader = "X-Real-IP"
	assert.Equal(t, nil, Validate(o))
	assert.Nil(t, o.GetRealClientIPParser())

	// Ensure simple use case works.
	o = testOptions()
	o.ReverseProxy = true
	o.RealClientIPHeader = "X-Forwarded-For"
	assert.Equal(t, nil, Validate(o))
	assert.NotNil(t, o.GetRealClientIPParser())

	// Ensure unknown header format process an error.
	o = testOptions()
	o.ReverseProxy = true
	o.RealClientIPHeader = "Forwarded"
	err := Validate(o)
	assert.NotEqual(t, nil, err)
	expected := errorMsg([]string{
		"real_client_ip_header (Forwarded) not accepted parameter value: the http header key (Forwarded) is either invalid or unsupported",
	})
	assert.Equal(t, expected, err.Error())
	assert.Nil(t, o.GetRealClientIPParser())

	// Ensure invalid header format produces an error.
	o = testOptions()
	o.ReverseProxy = true
	o.RealClientIPHeader = "!934invalidheader-23:"
	err = Validate(o)
	assert.NotEqual(t, nil, err)
	expected = errorMsg([]string{
		"real_client_ip_header (!934invalidheader-23:) not accepted parameter value: the http header key (!934invalidheader-23:) is either invalid or unsupported",
	})
	assert.Equal(t, expected, err.Error())
	assert.Nil(t, o.GetRealClientIPParser())
}

func TestIPCIDRSetOption(t *testing.T) {
	tests := []struct {
		name       string
		trustedIPs []string
		err        error
	}{
		{
			"TestSomeIPs",
			[]string{"127.0.0.1", "10.32.0.1/32", "43.36.201.0/24", "::1", "2a12:105:ee7:9234:0:0:0:0/64"},
			nil,
		}, {
			"TestOverlappingIPs",
			[]string{"135.180.78.199", "135.180.78.199/32", "d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4", "d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128"},
			nil,
		}, {
			"TestInvalidIPs",
			[]string{"[::1]", "alkwlkbn/32"},
			errors.New(
				"invalid configuration:\n" +
					"  trusted_ips[0] ([::1]) could not be recognized\n" +
					"  trusted_ips[1] (alkwlkbn/32) could not be recognized",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := testOptions()
			o.TrustedIPs = tt.trustedIPs
			err := Validate(o)
			if tt.err == nil {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, tt.err.Error(), err.Error())
			}
		})
	}
}

func TestProviderCAFilesError(t *testing.T) {
	file, err := ioutil.TempFile("", "absent.*.crt")
	assert.NoError(t, err)
	assert.NoError(t, file.Close())
	assert.NoError(t, os.Remove(file.Name()))

	o := testOptions()
	o.ProviderCAFiles = append(o.ProviderCAFiles, file.Name())
	err = Validate(o)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to load provider CA file(s)")
}
