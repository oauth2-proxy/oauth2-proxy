package validation

import (
	"bytes"
	"crypto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cookieSecret = "secretthirtytwobytes+abcdefghijk"
	clientID     = "bazquux"
	clientSecret = "xyzzyplugh"
	providerID   = "providerID"
)

func testOptions() *options.Options {
	o := options.NewOptions()
	o.UpstreamServers.Upstreams = append(o.UpstreamServers.Upstreams, options.Upstream{
		ID:   "upstream",
		Path: "/",
		URI:  "http://127.0.0.1:8080/",
	})
	o.Cookie.Secret = cookieSecret
	o.Providers[0].ID = providerID
	o.Providers[0].ClientID = clientID
	o.Providers[0].ClientSecret = clientSecret
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
		"missing setting: cookie-secret or cookie-secret-file",
		"provider has empty id: ids are required for all providers",
		"provider missing setting: client-id",
		"missing setting: client-secret or client-secret-file"})
	assert.Equal(t, expected, err.Error())
}

func TestGoogleGroupOptionsWithoutServiceAccountJSON(t *testing.T) {
	o := testOptions()
	o.Providers[0].GoogleConfig.AdminEmail = "admin@example.com"
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: google-service-account-json or google-use-application-default-credentials"})
	assert.Equal(t, expected, err.Error())
}

func TestGoogleGroupOptionsWithoutAdminEmail(t *testing.T) {
	o := testOptions()
	o.Providers[0].GoogleConfig.UseApplicationDefaultCredentials = ptr.To(true)
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: google-admin-email"})
	assert.Equal(t, expected, err.Error())
}

func TestGoogleGroupOptionsWithoutGroups(t *testing.T) {
	o := testOptions()
	// Set admin email and application default credentials but no groups - should still require them
	o.Providers[0].GoogleConfig.AdminEmail = "admin@example.com"
	o.Providers[0].GoogleConfig.UseApplicationDefaultCredentials = ptr.To(true)
	err := Validate(o)
	// Should pass validation since google-group is now optional
	assert.Equal(t, nil, err)
}

func TestGoogleGroupInvalidFile(t *testing.T) {
	o := testOptions()
	o.Providers[0].GoogleConfig.Groups = []string{"test_group"}
	o.Providers[0].GoogleConfig.AdminEmail = "admin@example.com"
	o.Providers[0].GoogleConfig.ServiceAccountJSON = "file_doesnt_exist.json"
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"Google credentials file not found: file_doesnt_exist.json",
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

func TestRealClientIPLogging(t *testing.T) {
	t.Cleanup(func() {
		logger.SetOutput(ginkgo.GinkgoWriter)
		logger.SetAuthTemplate(logger.DefaultAuthLoggingFormat)
		logger.SetReqTemplate(logger.DefaultRequestLoggingFormat)
		logger.SetGetClientFunc(func(r *http.Request) string { return r.RemoteAddr })
	})
	tests := []struct {
		name         string
		remoteAddr   string
		headerValues []string
		reverseProxy bool
		nilParser    bool
		expected     string
	}{
		{"Untrusted peer", "198.51.100.23:1234", []string{"10.0.0.5"}, true, false, "198.51.100.23"},
		{"Appending trusted proxy", "192.0.2.10:1234", []string{"10.0.0.5, 198.51.100.23"}, true, false, "198.51.100.23"},
		{"Repeated fields and multiple proxies", "192.0.2.10:1234", []string{"10.0.0.5", "198.51.100.23, 192.0.2.20", "192.0.2.21"}, true, false, "198.51.100.23"},
		{"Legitimate client", "192.0.2.10:1234", []string{"10.0.0.5, 192.0.2.20"}, true, false, "10.0.0.5"},
		{"Missing header", "192.0.2.10:1234", nil, true, false, "192.0.2.10"},
		{"Malformed relevant hop", "192.0.2.10:1234", []string{"10.0.0.5, invalid, 192.0.2.20"}, true, false, "192.0.2.10"},
		{"Nil parser", "192.0.2.10:1234", []string{"10.0.0.5"}, true, true, "192.0.2.10"},
		{"Reverse proxy disabled in scope", "192.0.2.10:1234", []string{"10.0.0.5"}, false, false, "192.0.2.10"},
		{"IPv6", "[2001:db8:1::10]:1234", []string{"10.0.0.5", " [2001:db8:2::23]:443 , 2001:db8:1::20"}, true, false, "2001:db8:2::23"},
		{"Unix socket", "@", []string{"10.0.0.5, 198.51.100.23"}, true, false, "198.51.100.23"},
		{"Entire chain trusted", "192.0.2.10:1234", []string{"192.0.2.30, 192.0.2.20"}, true, false, "192.0.2.30"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := testOptions()
			o.ReverseProxy = true
			o.RealClientIPHeader = "X-Forwarded-For"
			o.TrustedProxyIPs = []string{"192.0.2.0/24", "2001:db8:1::/48"}
			o.Logging.AuthFormat = "{{.Client}}"
			o.Logging.RequestFormat = "{{.Client}}"
			require.NoError(t, Validate(o))
			if test.nilParser {
				o.SetRealClientIPParser(nil)
			}
			trustedProxies, err := ip.ParseNetSet(o.TrustedProxyIPs)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = test.remoteAddr
			for _, value := range test.headerValues {
				req.Header.Add("X-Forwarded-For", value)
			}
			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
				ReverseProxy:   test.reverseProxy,
				TrustedProxies: trustedProxies,
			})
			var output bytes.Buffer
			logger.SetOutput(&output)
			logger.PrintAuthf("", req, logger.AuthFailure, "denied")
			logger.PrintReq("", "", req, *req.URL, time.Now(), http.StatusForbidden, 0)
			assert.Equal(t, test.expected+"\n"+test.expected+"\n", output.String())
		})
	}
}

func TestProviderCAFilesError(t *testing.T) {
	file, err := os.CreateTemp("", "absent.*.crt")
	assert.NoError(t, err)
	assert.NoError(t, file.Close())
	assert.NoError(t, os.Remove(file.Name()))

	o := testOptions()
	o.Providers[0].CAFiles = append(o.Providers[0].CAFiles, file.Name())
	err = Validate(o)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to load provider CA file(s)")
}
