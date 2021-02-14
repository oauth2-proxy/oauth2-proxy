package main

import (
	"bufio"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	sessionscookie "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/upstream"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// The rawCookieSecret is 32 bytes and the base64CookieSecret is the base64
	// encoded version of this.
	rawCookieSecret    = "secretthirtytwobytes+abcdefghijk"
	base64CookieSecret = "c2VjcmV0dGhpcnR5dHdvYnl0ZXMrYWJjZGVmZ2hpams"
	clientID           = "3984n253984d7348dm8234yf982t"
	clientSecret       = "gv3498mfc9t23y23974dm2394dm9"
)

func init() {
	logger.SetFlags(logger.Lshortfile)
}

func TestRobotsTxt(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	assert.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/robots.txt", nil)
	proxy.ServeHTTP(rw, req)
	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "User-agent: *\nDisallow: /", rw.Body.String())
}

func TestIsValidRedirect(t *testing.T) {
	opts := baseTestOptions()
	// Should match domains that are exactly foo.bar and any subdomain of bar.foo
	opts.WhitelistDomains = []string{
		"foo.bar",
		".bar.foo",
		"port.bar:8080",
		".sub.port.bar:8080",
		"anyport.bar:*",
		".sub.anyport.bar:*",
	}
	err := validation.Validate(opts)
	assert.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		Desc, Redirect string
		ExpectedResult bool
	}{
		{
			Desc:           "noRD",
			Redirect:       "",
			ExpectedResult: false,
		},
		{
			Desc:           "singleSlash",
			Redirect:       "/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "doubleSlash",
			Redirect:       "//redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "validHTTP",
			Redirect:       "http://foo.bar/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "validHTTPS",
			Redirect:       "https://foo.bar/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "invalidHTTPSubdomain",
			Redirect:       "http://baz.foo.bar/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidHTTPSSubdomain",
			Redirect:       "https://baz.foo.bar/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "validHTTPSubdomain",
			Redirect:       "http://baz.bar.foo/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "validHTTPSSubdomain",
			Redirect:       "https://baz.bar.foo/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "validHTTPDomain",
			Redirect:       "http://bar.foo/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "invalidHTTP1",
			Redirect:       "http://foo.bar.evil.corp/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidHTTPS1",
			Redirect:       "https://foo.bar.evil.corp/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidHTTP2",
			Redirect:       "http://evil.corp/redirect?rd=foo.bar",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidHTTPS2",
			Redirect:       "https://evil.corp/redirect?rd=foo.bar",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidPort",
			Redirect:       "https://evil.corp:3838/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidEmptyPort",
			Redirect:       "http://foo.bar:3838/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "invalidEmptyPortSubdomain",
			Redirect:       "http://baz.bar.foo:3838/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "validSpecificPort",
			Redirect:       "http://port.bar:8080/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "invalidSpecificPort",
			Redirect:       "http://port.bar:3838/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "validSpecificPortSubdomain",
			Redirect:       "http://foo.sub.port.bar:8080/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "invalidSpecificPortSubdomain",
			Redirect:       "http://foo.sub.port.bar:3838/redirect",
			ExpectedResult: false,
		},
		{
			Desc:           "validAnyPort1",
			Redirect:       "http://anyport.bar:8080/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "validAnyPort2",
			Redirect:       "http://anyport.bar:8081/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "validAnyPortSubdomain1",
			Redirect:       "http://a.sub.anyport.bar:8080/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "validAnyPortSubdomain2",
			Redirect:       "http://a.sub.anyport.bar:8081/redirect",
			ExpectedResult: true,
		},
		{
			Desc:           "openRedirect1",
			Redirect:       "/\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectSpace1",
			Redirect:       "/ /evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectSpace2",
			Redirect:       "/ \\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectTab1",
			Redirect:       "/\t/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectTab2",
			Redirect:       "/\t\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectVerticalTab1",
			Redirect:       "/\v/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectVerticalTab2",
			Redirect:       "/\v\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectNewLine1",
			Redirect:       "/\n/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectNewLine2",
			Redirect:       "/\n\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectCarriageReturn1",
			Redirect:       "/\r/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectCarriageReturn2",
			Redirect:       "/\r\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectTripleTab",
			Redirect:       "/\t\t/\t/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectTripleTab2",
			Redirect:       "/\t\t\\\t/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectQuadTab1",
			Redirect:       "/\t\t/\t\t\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectQuadTab2",
			Redirect:       "/\t\t\\\t\t/evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectPeriod1",
			Redirect:       "/./\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectPeriod2",
			Redirect:       "/./../../\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectDoubleTab",
			Redirect:       "/\t/\t\\evil.com",
			ExpectedResult: false,
		},
		{
			Desc:           "openRedirectPartialSubdomain",
			Redirect:       "http://evilbar.foo",
			ExpectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Desc, func(t *testing.T) {
			result := proxy.IsValidRedirect(tc.Redirect)

			if result != tc.ExpectedResult {
				t.Errorf("expected %t got %t", tc.ExpectedResult, result)
			}
		})
	}
}

func TestOpenRedirects(t *testing.T) {
	opts := baseTestOptions()
	// Should match domains that are exactly foo.bar and any subdomain of bar.foo
	opts.WhitelistDomains = []string{
		"foo.bar",
		".bar.foo",
		"port.bar:8080",
		".sub.port.bar:8080",
		"anyport.bar:*",
		".sub.anyport.bar:*",
		"www.whitelisteddomain.tld",
	}
	err := validation.Validate(opts)
	assert.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Open("./testdata/openredirects.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func(t *testing.T) {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}(t)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rd := scanner.Text()
		t.Run(rd, func(t *testing.T) {
			rdUnescaped, err := url.QueryUnescape(rd)
			if err != nil {
				t.Fatal(err)
			}
			if proxy.IsValidRedirect(rdUnescaped) {
				t.Errorf("Expected %q to not be valid (unescaped: %q)", rd, rdUnescaped)
			}
		})
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

type TestProvider struct {
	*providers.ProviderData
	EmailAddress   string
	ValidToken     bool
	GroupValidator func(string) bool
}

var _ providers.Provider = (*TestProvider)(nil)

func NewTestProvider(providerURL *url.URL, emailAddress string) *TestProvider {
	return &TestProvider{
		ProviderData: &providers.ProviderData{
			ProviderName: "Test Provider",
			LoginURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/api/v1/profile",
			},
			Scope: "profile.email",
		},
		EmailAddress: emailAddress,
		GroupValidator: func(s string) bool {
			return true
		},
	}
}

func (tp *TestProvider) GetEmailAddress(_ context.Context, _ *sessions.SessionState) (string, error) {
	return tp.EmailAddress, nil
}

func (tp *TestProvider) ValidateSession(_ context.Context, _ *sessions.SessionState) bool {
	return tp.ValidToken
}

func Test_redeemCode(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	assert.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = proxy.redeemCode(req)
	assert.Equal(t, providers.ErrMissingCode, err)
}

func Test_enrichSession(t *testing.T) {
	const (
		sessionUser   = "Mr Session"
		sessionEmail  = "session@example.com"
		providerEmail = "provider@example.com"
	)

	testCases := map[string]struct {
		session       *sessions.SessionState
		expectedUser  string
		expectedEmail string
	}{
		"Session already has enrichable fields": {
			session: &sessions.SessionState{
				User:  sessionUser,
				Email: sessionEmail,
			},
			expectedUser:  sessionUser,
			expectedEmail: sessionEmail,
		},
		"Session is missing Email and GetEmailAddress is implemented": {
			session: &sessions.SessionState{
				User: sessionUser,
			},
			expectedUser:  sessionUser,
			expectedEmail: providerEmail,
		},
		"Session is missing User and GetUserName is not implemented": {
			session: &sessions.SessionState{
				Email: sessionEmail,
			},
			expectedUser:  "",
			expectedEmail: sessionEmail,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			opts := baseTestOptions()
			err := validation.Validate(opts)
			assert.NoError(t, err)

			// intentionally set after validation.Validate(opts) since it will clobber
			// our TestProvider and call `providers.New` defaulting to `providers.GoogleProvider`
			opts.SetProvider(NewTestProvider(&url.URL{Host: "www.example.com"}, providerEmail))
			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}

			err = proxy.enrichSessionState(context.Background(), tc.session)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedUser, tc.session.User)
			assert.Equal(t, tc.expectedEmail, tc.session.Email)
		})
	}
}

func TestBasicAuthPassword(t *testing.T) {
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%#v", r)
		var payload string
		switch r.URL.Path {
		case "/oauth/token":
			payload = `{"access_token": "my_auth_token"}`
		default:
			payload = r.Header.Get("Authorization")
			if payload == "" {
				payload = "No Authorization header found."
			}
		}
		w.WriteHeader(200)
		_, err := w.Write([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
	}))

	basicAuthPassword := "This is a secure password"
	opts := baseTestOptions()
	opts.UpstreamServers = options.Upstreams{
		{
			ID:   providerServer.URL,
			Path: "/",
			URI:  providerServer.URL,
		},
	}

	opts.Cookie.Secure = false
	opts.InjectRequestHeaders = []options.Header{
		{
			Name: "Authorization",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "email",
						BasicAuthPassword: &options.SecretSource{
							Value: []byte(basicAuthPassword),
						},
					},
				},
			},
		},
	}

	err := validation.Validate(opts)
	assert.NoError(t, err)

	providerURL, _ := url.Parse(providerServer.URL)
	const emailAddress = "john.doe@example.com"

	opts.SetProvider(NewTestProvider(providerURL, emailAddress))
	proxy, err := NewOAuthProxy(opts, func(email string) bool {
		return email == emailAddress
	})
	if err != nil {
		t.Fatal(err)
	}

	// Save the required session
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	err = proxy.sessionStore.Save(rw, req, &sessions.SessionState{
		Email: emailAddress,
	})
	assert.NoError(t, err)

	// Extract the cookie value to inject into the test request
	cookie := rw.Header().Values("Set-Cookie")[0]

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", cookie)
	rw = httptest.NewRecorder()
	proxy.ServeHTTP(rw, req)

	// The username in the basic auth credentials is expected to be equal to the email address from the
	// auth response, so we use the same variable here.
	expectedHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(emailAddress+":"+basicAuthPassword))
	assert.Equal(t, expectedHeader, rw.Body.String())
	providerServer.Close()
}

func TestPassGroupsHeadersWithGroups(t *testing.T) {
	opts := baseTestOptions()
	opts.InjectRequestHeaders = []options.Header{
		{
			Name: "X-Forwarded-Groups",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	err := validation.Validate(opts)
	assert.NoError(t, err)

	const emailAddress = "john.doe@example.com"
	const userName = "9fcab5c9b889a557"

	groups := []string{"a", "b"}
	created := time.Now()
	session := &sessions.SessionState{
		User:        userName,
		Groups:      groups,
		Email:       emailAddress,
		AccessToken: "oauth_token",
		CreatedAt:   &created,
	}

	proxy, err := NewOAuthProxy(opts, func(email string) bool {
		return email == emailAddress
	})
	assert.NoError(t, err)

	// Save the required session
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	err = proxy.sessionStore.Save(rw, req, session)
	assert.NoError(t, err)

	// Extract the cookie value to inject into the test request
	cookie := rw.Header().Values("Set-Cookie")[0]

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", cookie)
	rw = httptest.NewRecorder()
	proxy.ServeHTTP(rw, req)

	assert.Equal(t, []string{"a,b"}, req.Header["X-Forwarded-Groups"])
}

type PassAccessTokenTest struct {
	providerServer *httptest.Server
	proxy          *OAuthProxy
	opts           *options.Options
}

type PassAccessTokenTestOptions struct {
	PassAccessToken bool
	ProxyUpstream   options.Upstream
}

func NewPassAccessTokenTest(opts PassAccessTokenTestOptions) (*PassAccessTokenTest, error) {
	patt := &PassAccessTokenTest{}

	patt.providerServer = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload string
			switch r.URL.Path {
			case "/oauth/token":
				payload = `{"access_token": "my_auth_token"}`
			default:
				payload = r.Header.Get("X-Forwarded-Access-Token")
				if payload == "" {
					payload = "No access token found."
				}
			}
			w.WriteHeader(200)
			_, err := w.Write([]byte(payload))
			if err != nil {
				panic(err)
			}
		}))

	patt.opts = baseTestOptions()
	patt.opts.UpstreamServers = options.Upstreams{
		{
			ID:   patt.providerServer.URL,
			Path: "/",
			URI:  patt.providerServer.URL,
		},
	}
	if opts.ProxyUpstream.ID != "" {
		patt.opts.UpstreamServers = append(patt.opts.UpstreamServers, opts.ProxyUpstream)
	}

	patt.opts.Cookie.Secure = false
	if opts.PassAccessToken {
		patt.opts.InjectRequestHeaders = []options.Header{
			{
				Name: "X-Forwarded-Access-Token",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim: "access_token",
						},
					},
				},
			},
		}
	}

	err := validation.Validate(patt.opts)
	if err != nil {
		return nil, err
	}

	providerURL, _ := url.Parse(patt.providerServer.URL)
	const emailAddress = "michael.bland@gsa.gov"

	patt.opts.SetProvider(NewTestProvider(providerURL, emailAddress))
	patt.proxy, err = NewOAuthProxy(patt.opts, func(email string) bool {
		return email == emailAddress
	})
	if err != nil {
		return nil, err
	}
	return patt, nil
}

func (patTest *PassAccessTokenTest) Close() {
	patTest.providerServer.Close()
}

func (patTest *PassAccessTokenTest) getCallbackEndpoint() (httpCode int,
	cookie string) {
	rw := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/oauth2/callback?code=callback_code&state=nonce:",
		strings.NewReader(""))
	if err != nil {
		return 0, ""
	}
	req.AddCookie(patTest.proxy.MakeCSRFCookie(req, "nonce", time.Hour, time.Now()))
	patTest.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Header().Values("Set-Cookie")[1]
}

// getEndpointWithCookie makes a requests againt the oauthproxy with passed requestPath
// and cookie and returns body and status code.
func (patTest *PassAccessTokenTest) getEndpointWithCookie(cookie string, endpoint string) (httpCode int, accessToken string) {
	cookieName := patTest.proxy.CookieName
	var value string
	keyPrefix := cookieName + "="

	for _, field := range strings.Split(cookie, "; ") {
		value = strings.TrimPrefix(field, keyPrefix)
		if value != field {
			break
		} else {
			value = ""
		}
	}
	if value == "" {
		return 0, ""
	}

	req, err := http.NewRequest("GET", endpoint, strings.NewReader(""))
	if err != nil {
		return 0, ""
	}
	req.AddCookie(&http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(time.Duration(24)),
		HttpOnly: true,
	})

	rw := httptest.NewRecorder()
	patTest.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestForwardAccessTokenUpstream(t *testing.T) {
	patTest, err := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(patTest.Close)

	// A successful validation will redirect and set the auth cookie.
	code, cookie := patTest.getCallbackEndpoint()
	if code != 302 {
		t.Fatalf("expected 302; got %d", code)
	}
	assert.NotNil(t, cookie)

	// Now we make a regular request; the access_token from the cookie is
	// forwarded as the "X-Forwarded-Access-Token" header. The token is
	// read by the test provider server and written in the response body.
	code, payload := patTest.getEndpointWithCookie(cookie, "/")
	if code != 200 {
		t.Fatalf("expected 200; got %d", code)
	}
	assert.Equal(t, "my_auth_token", payload)
}

func TestStaticProxyUpstream(t *testing.T) {
	patTest, err := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: true,
		ProxyUpstream: options.Upstream{
			ID:     "static-proxy",
			Path:   "/static-proxy",
			Static: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(patTest.Close)

	// A successful validation will redirect and set the auth cookie.
	code, cookie := patTest.getCallbackEndpoint()
	if code != 302 {
		t.Fatalf("expected 302; got %d", code)
	}
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request against the upstream proxy; And validate
	// the returned status code through the static proxy.
	code, payload := patTest.getEndpointWithCookie(cookie, "/static-proxy")
	if code != 200 {
		t.Fatalf("expected 200; got %d", code)
	}
	assert.Equal(t, "Authenticated", payload)
}

func TestDoNotForwardAccessTokenUpstream(t *testing.T) {
	patTest, err := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(patTest.Close)

	// A successful validation will redirect and set the auth cookie.
	code, cookie := patTest.getCallbackEndpoint()
	if code != 302 {
		t.Fatalf("expected 302; got %d", code)
	}
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request, but the access token header should
	// not be present.
	code, payload := patTest.getEndpointWithCookie(cookie, "/")
	if code != 200 {
		t.Fatalf("expected 200; got %d", code)
	}
	assert.Equal(t, "No access token found.", payload)
}

type SignInPageTest struct {
	opts                 *options.Options
	proxy                *OAuthProxy
	signInRegexp         *regexp.Regexp
	signInProviderRegexp *regexp.Regexp
}

const signInRedirectPattern = `<input type="hidden" name="rd" value="(.*)">`
const signInSkipProvider = `>Found<`

func NewSignInPageTest(skipProvider bool) (*SignInPageTest, error) {
	var sipTest SignInPageTest

	sipTest.opts = baseTestOptions()
	sipTest.opts.SkipProviderButton = skipProvider
	err := validation.Validate(sipTest.opts)
	if err != nil {
		return nil, err
	}

	sipTest.proxy, err = NewOAuthProxy(sipTest.opts, func(email string) bool {
		return true
	})
	if err != nil {
		return nil, err
	}
	sipTest.signInRegexp = regexp.MustCompile(signInRedirectPattern)
	sipTest.signInProviderRegexp = regexp.MustCompile(signInSkipProvider)

	return &sipTest, nil
}

func (sipTest *SignInPageTest) GetEndpoint(endpoint string) (int, string) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", endpoint, strings.NewReader(""))
	sipTest.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestSignInPageIncludesTargetRedirect(t *testing.T) {
	sipTest, err := NewSignInPageTest(false)
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "/some/random/endpoint"

	code, body := sipTest.GetEndpoint(endpoint)
	assert.Equal(t, 403, code)

	match := sipTest.signInRegexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInRedirectPattern + "\nBody:\n" + body)
	}
	if match[1] != endpoint {
		t.Fatal(`expected redirect to "` + endpoint +
			`", but was "` + match[1] + `"`)
	}
}

func TestSignInPageDirectAccessRedirectsToRoot(t *testing.T) {
	sipTest, err := NewSignInPageTest(false)
	if err != nil {
		t.Fatal(err)
	}
	code, body := sipTest.GetEndpoint("/oauth2/sign_in")
	assert.Equal(t, 200, code)

	match := sipTest.signInRegexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInRedirectPattern + "\nBody:\n" + body)
	}
	if match[1] != "/" {
		t.Fatal(`expected redirect to "/", but was "` + match[1] + `"`)
	}
}

func TestSignInPageSkipProvider(t *testing.T) {
	sipTest, err := NewSignInPageTest(true)
	if err != nil {
		t.Fatal(err)
	}

	endpoint := "/some/random/endpoint"

	code, body := sipTest.GetEndpoint(endpoint)
	assert.Equal(t, 302, code)

	match := sipTest.signInProviderRegexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInSkipProvider + "\nBody:\n" + body)
	}
}

func TestSignInPageSkipProviderDirect(t *testing.T) {
	sipTest, err := NewSignInPageTest(true)
	if err != nil {
		t.Fatal(err)
	}

	endpoint := "/sign_in"

	code, body := sipTest.GetEndpoint(endpoint)
	assert.Equal(t, 302, code)

	match := sipTest.signInProviderRegexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInSkipProvider + "\nBody:\n" + body)
	}
}

type ProcessCookieTest struct {
	opts         *options.Options
	proxy        *OAuthProxy
	rw           *httptest.ResponseRecorder
	req          *http.Request
	validateUser bool
}

type ProcessCookieTestOpts struct {
	providerValidateCookieResponse bool
}

type OptionsModifier func(*options.Options)

func NewProcessCookieTest(opts ProcessCookieTestOpts, modifiers ...OptionsModifier) (*ProcessCookieTest, error) {
	var pcTest ProcessCookieTest

	pcTest.opts = baseTestOptions()
	for _, modifier := range modifiers {
		modifier(pcTest.opts)
	}
	// First, set the CookieRefresh option so proxy.AesCipher is created,
	// needed to encrypt the access_token.
	pcTest.opts.Cookie.Refresh = time.Hour
	err := validation.Validate(pcTest.opts)
	if err != nil {
		return nil, err
	}

	pcTest.proxy, err = NewOAuthProxy(pcTest.opts, func(email string) bool {
		return pcTest.validateUser
	})
	if err != nil {
		return nil, err
	}
	pcTest.proxy.provider = &TestProvider{
		ProviderData: &providers.ProviderData{},
		ValidToken:   opts.providerValidateCookieResponse,
	}
	pcTest.proxy.provider.(*TestProvider).SetAllowedGroups(pcTest.opts.AllowedGroups)

	// Now, zero-out proxy.CookieRefresh for the cases that don't involve
	// access_token validation.
	pcTest.proxy.CookieRefresh = time.Duration(0)
	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET", "/", strings.NewReader(""))
	pcTest.validateUser = true
	return &pcTest, nil
}

func NewProcessCookieTestWithDefaults() (*ProcessCookieTest, error) {
	return NewProcessCookieTest(ProcessCookieTestOpts{
		providerValidateCookieResponse: true,
	})
}

func NewProcessCookieTestWithOptionsModifiers(modifiers ...OptionsModifier) (*ProcessCookieTest, error) {
	return NewProcessCookieTest(ProcessCookieTestOpts{
		providerValidateCookieResponse: true,
	}, modifiers...)
}

func (p *ProcessCookieTest) SaveSession(s *sessions.SessionState) error {
	err := p.proxy.SaveSession(p.rw, p.req, s)
	if err != nil {
		return err
	}
	for _, cookie := range p.rw.Result().Cookies() {
		p.req.AddCookie(cookie)
	}
	return nil
}

func (p *ProcessCookieTest) LoadCookiedSession() (*sessions.SessionState, error) {
	return p.proxy.LoadCookiedSession(p.req)
}

func TestLoadCookiedSession(t *testing.T) {
	pcTest, err := NewProcessCookieTestWithDefaults()
	if err != nil {
		t.Fatal(err)
	}

	created := time.Now()
	startSession := &sessions.SessionState{Email: "john.doe@example.com", AccessToken: "my_access_token", CreatedAt: &created}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	session, err := pcTest.LoadCookiedSession()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, startSession.Email, session.Email)
	assert.Equal(t, "", session.User)
	assert.Equal(t, startSession.AccessToken, session.AccessToken)
}

func TestProcessCookieNoCookieError(t *testing.T) {
	pcTest, err := NewProcessCookieTestWithDefaults()
	if err != nil {
		t.Fatal(err)
	}

	session, err := pcTest.LoadCookiedSession()
	assert.Error(t, err, "cookie \"_oauth2_proxy\" not present")
	if session != nil {
		t.Errorf("expected nil session. got %#v", session)
	}
}

func TestProcessCookieRefreshNotSet(t *testing.T) {
	pcTest, err := NewProcessCookieTestWithOptionsModifiers(func(opts *options.Options) {
		opts.Cookie.Expire = time.Duration(23) * time.Hour
	})
	if err != nil {
		t.Fatal(err)
	}

	reference := time.Now().Add(time.Duration(-2) * time.Hour)

	startSession := &sessions.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: &reference}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	session, err := pcTest.LoadCookiedSession()
	assert.Equal(t, nil, err)
	if session.Age() < time.Duration(-2)*time.Hour {
		t.Errorf("cookie too young %v", session.Age())
	}
	assert.Equal(t, startSession.Email, session.Email)
}

func TestProcessCookieFailIfCookieExpired(t *testing.T) {
	pcTest, err := NewProcessCookieTestWithOptionsModifiers(func(opts *options.Options) {
		opts.Cookie.Expire = time.Duration(24) * time.Hour
	})
	if err != nil {
		t.Fatal(err)
	}

	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &sessions.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: &reference}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	session, err := pcTest.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func TestProcessCookieFailIfRefreshSetAndCookieExpired(t *testing.T) {
	pcTest, err := NewProcessCookieTestWithOptionsModifiers(func(opts *options.Options) {
		opts.Cookie.Expire = time.Duration(24) * time.Hour
	})
	if err != nil {
		t.Fatal(err)
	}

	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &sessions.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: &reference}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	pcTest.proxy.CookieRefresh = time.Hour
	session, err := pcTest.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func NewUserInfoEndpointTest() (*ProcessCookieTest, error) {
	pcTest, err := NewProcessCookieTestWithDefaults()
	if err != nil {
		return nil, err
	}
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/userinfo", nil)
	return pcTest, nil
}

func TestUserInfoEndpointAccepted(t *testing.T) {
	testCases := []struct {
		name             string
		session          *sessions.SessionState
		expectedResponse string
	}{
		{
			name: "Full session",
			session: &sessions.SessionState{
				User:        "john.doe",
				Email:       "john.doe@example.com",
				Groups:      []string{"example", "groups"},
				AccessToken: "my_access_token",
			},
			expectedResponse: "{\"user\":\"john.doe\",\"email\":\"john.doe@example.com\",\"groups\":[\"example\",\"groups\"]}\n",
		},
		{
			name: "Minimal session",
			session: &sessions.SessionState{
				User:   "john.doe",
				Email:  "john.doe@example.com",
				Groups: []string{"example", "groups"},
			},
			expectedResponse: "{\"user\":\"john.doe\",\"email\":\"john.doe@example.com\",\"groups\":[\"example\",\"groups\"]}\n",
		},
		{
			name: "No groups",
			session: &sessions.SessionState{
				User:        "john.doe",
				Email:       "john.doe@example.com",
				AccessToken: "my_access_token",
			},
			expectedResponse: "{\"user\":\"john.doe\",\"email\":\"john.doe@example.com\"}\n",
		},
		{
			name: "With Preferred Username",
			session: &sessions.SessionState{
				User:              "john.doe",
				PreferredUsername: "john",
				Email:             "john.doe@example.com",
				Groups:            []string{"example", "groups"},
				AccessToken:       "my_access_token",
			},
			expectedResponse: "{\"user\":\"john.doe\",\"email\":\"john.doe@example.com\",\"groups\":[\"example\",\"groups\"],\"preferredUsername\":\"john\"}\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test, err := NewUserInfoEndpointTest()
			if err != nil {
				t.Fatal(err)
			}
			err = test.SaveSession(tc.session)
			assert.NoError(t, err)

			test.proxy.ServeHTTP(test.rw, test.req)
			assert.Equal(t, http.StatusOK, test.rw.Code)
			bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
			assert.Equal(t, tc.expectedResponse, string(bodyBytes))
		})
	}
}

func TestUserInfoEndpointUnauthorizedOnNoCookieSetError(t *testing.T) {
	test, err := NewUserInfoEndpointTest()
	if err != nil {
		t.Fatal(err)
	}

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
}

func NewAuthOnlyEndpointTest(querystring string, modifiers ...OptionsModifier) (*ProcessCookieTest, error) {
	pcTest, err := NewProcessCookieTestWithOptionsModifiers(modifiers...)
	if err != nil {
		return nil, err
	}
	pcTest.req, _ = http.NewRequest(
		"GET",
		fmt.Sprintf("%s/auth%s", pcTest.opts.ProxyPrefix, querystring),
		nil)
	return pcTest, nil
}

func TestAuthOnlyEndpointAccepted(t *testing.T) {
	test, err := NewAuthOnlyEndpointTest("")
	if err != nil {
		t.Fatal(err)
	}

	created := time.Now()
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: &created}
	err = test.SaveSession(startSession)
	assert.NoError(t, err)

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusAccepted, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnNoCookieSetError(t *testing.T) {
	test, err := NewAuthOnlyEndpointTest("")
	if err != nil {
		t.Fatal(err)
	}

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "Unauthorized\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnExpiration(t *testing.T) {
	test, err := NewAuthOnlyEndpointTest("", func(opts *options.Options) {
		opts.Cookie.Expire = time.Duration(24) * time.Hour
	})
	if err != nil {
		t.Fatal(err)
	}

	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: &reference}
	err = test.SaveSession(startSession)
	assert.NoError(t, err)

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "Unauthorized\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnEmailValidationFailure(t *testing.T) {
	test, err := NewAuthOnlyEndpointTest("")
	if err != nil {
		t.Fatal(err)
	}

	created := time.Now()
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: &created}
	err = test.SaveSession(startSession)
	assert.NoError(t, err)
	test.validateUser = false

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "Unauthorized\n", string(bodyBytes))
}

func TestAuthOnlyEndpointSetXAuthRequestHeaders(t *testing.T) {
	var pcTest ProcessCookieTest

	pcTest.opts = baseTestOptions()
	pcTest.opts.InjectResponseHeaders = []options.Header{
		{
			Name: "X-Auth-Request-User",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
		{
			Name: "X-Forwarded-Preferred-Username",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
	}
	pcTest.opts.AllowedGroups = []string{"oauth_groups"}
	err := validation.Validate(pcTest.opts)
	assert.NoError(t, err)

	pcTest.proxy, err = NewOAuthProxy(pcTest.opts, func(email string) bool {
		return pcTest.validateUser
	})
	if err != nil {
		t.Fatal(err)
	}
	pcTest.proxy.provider = &TestProvider{
		ProviderData: &providers.ProviderData{},
		ValidToken:   true,
	}

	pcTest.validateUser = true

	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/auth", nil)

	created := time.Now()
	startSession := &sessions.SessionState{
		User: "oauth_user", Groups: []string{"oauth_groups"}, Email: "oauth_user@example.com", AccessToken: "oauth_token", CreatedAt: &created}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	pcTest.proxy.ServeHTTP(pcTest.rw, pcTest.req)
	assert.Equal(t, http.StatusAccepted, pcTest.rw.Code)
	assert.Equal(t, "oauth_user", pcTest.rw.Header().Get("X-Auth-Request-User"))
	assert.Equal(t, startSession.Groups, pcTest.rw.Header().Values("X-Auth-Request-Groups"))
	assert.Equal(t, "oauth_user@example.com", pcTest.rw.Header().Get("X-Auth-Request-Email"))
}

func TestAuthOnlyEndpointSetBasicAuthTrueRequestHeaders(t *testing.T) {
	var pcTest ProcessCookieTest

	pcTest.opts = baseTestOptions()
	pcTest.opts.InjectResponseHeaders = []options.Header{
		{
			Name: "X-Auth-Request-User",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
		{
			Name: "X-Forwarded-Preferred-Username",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
		{
			Name: "Authorization",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "user",
						BasicAuthPassword: &options.SecretSource{
							Value: []byte("This is a secure password"),
						},
					},
				},
			},
		},
	}

	err := validation.Validate(pcTest.opts)
	assert.NoError(t, err)

	pcTest.proxy, err = NewOAuthProxy(pcTest.opts, func(email string) bool {
		return pcTest.validateUser
	})
	if err != nil {
		t.Fatal(err)
	}
	pcTest.proxy.provider = &TestProvider{
		ProviderData: &providers.ProviderData{},
		ValidToken:   true,
	}

	pcTest.validateUser = true

	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/auth", nil)

	created := time.Now()
	startSession := &sessions.SessionState{
		User: "oauth_user", Email: "oauth_user@example.com", AccessToken: "oauth_token", CreatedAt: &created}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	pcTest.proxy.ServeHTTP(pcTest.rw, pcTest.req)
	assert.Equal(t, http.StatusAccepted, pcTest.rw.Code)
	assert.Equal(t, "oauth_user", pcTest.rw.Header().Values("X-Auth-Request-User")[0])
	assert.Equal(t, "oauth_user@example.com", pcTest.rw.Header().Values("X-Auth-Request-Email")[0])
	expectedHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth_user:This is a secure password"))
	assert.Equal(t, expectedHeader, pcTest.rw.Header().Values("Authorization")[0])
}

func TestAuthOnlyEndpointSetBasicAuthFalseRequestHeaders(t *testing.T) {
	var pcTest ProcessCookieTest

	pcTest.opts = baseTestOptions()
	pcTest.opts.InjectResponseHeaders = []options.Header{
		{
			Name: "X-Auth-Request-User",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
		{
			Name: "X-Forwarded-Preferred-Username",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
	}
	err := validation.Validate(pcTest.opts)
	assert.NoError(t, err)

	pcTest.proxy, err = NewOAuthProxy(pcTest.opts, func(email string) bool {
		return pcTest.validateUser
	})
	if err != nil {
		t.Fatal(err)
	}
	pcTest.proxy.provider = &TestProvider{
		ProviderData: &providers.ProviderData{},
		ValidToken:   true,
	}

	pcTest.validateUser = true

	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/auth", nil)

	created := time.Now()
	startSession := &sessions.SessionState{
		User: "oauth_user", Email: "oauth_user@example.com", AccessToken: "oauth_token", CreatedAt: &created}
	err = pcTest.SaveSession(startSession)
	assert.NoError(t, err)

	pcTest.proxy.ServeHTTP(pcTest.rw, pcTest.req)
	assert.Equal(t, http.StatusAccepted, pcTest.rw.Code)
	assert.Equal(t, "oauth_user", pcTest.rw.Header().Values("X-Auth-Request-User")[0])
	assert.Equal(t, "oauth_user@example.com", pcTest.rw.Header().Values("X-Auth-Request-Email")[0])
	assert.Equal(t, 0, len(pcTest.rw.Header().Values("Authorization")), "should not have Authorization header entries")
}

func TestAuthSkippedForPreflightRequests(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("response"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.UpstreamServers = options.Upstreams{
		{
			ID:   upstreamServer.URL,
			Path: "/",
			URI:  upstreamServer.URL,
		},
	}
	opts.SkipAuthPreflight = true
	err := validation.Validate(opts)
	assert.NoError(t, err)

	upstreamURL, _ := url.Parse(upstreamServer.URL)
	opts.SetProvider(NewTestProvider(upstreamURL, ""))

	proxy, err := NewOAuthProxy(opts, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/preflight-request", nil)
	proxy.ServeHTTP(rw, req)

	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "response", rw.Body.String())
}

type SignatureAuthenticator struct {
	auth hmacauth.HmacAuth
}

func (v *SignatureAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) {
	result, headerSig, computedSig := v.auth.AuthenticateRequest(r)

	var msg string
	switch result {
	case hmacauth.ResultNoSignature:
		msg = "no signature received"
	case hmacauth.ResultMatch:
		msg = "signatures match"
	case hmacauth.ResultMismatch:
		msg = fmt.Sprintf(
			"signatures do not match:\n  received: %s\n  computed: %s",
			headerSig,
			computedSig)
	default:
		panic("unknown result value: " + result.String())
	}

	_, err := w.Write([]byte(msg))
	if err != nil {
		panic(err)
	}
}

type SignatureTest struct {
	opts          *options.Options
	upstream      *httptest.Server
	upstreamHost  string
	provider      *httptest.Server
	header        http.Header
	rw            *httptest.ResponseRecorder
	authenticator *SignatureAuthenticator
}

func NewSignatureTest() (*SignatureTest, error) {
	opts := baseTestOptions()
	opts.EmailDomains = []string{"acm.org"}

	authenticator := &SignatureAuthenticator{}
	upstreamServer := httptest.NewServer(
		http.HandlerFunc(authenticator.Authenticate))
	upstreamURL, err := url.Parse(upstreamServer.URL)
	if err != nil {
		return nil, err
	}
	opts.UpstreamServers = options.Upstreams{
		{
			ID:   upstreamServer.URL,
			Path: "/",
			URI:  upstreamServer.URL,
		},
	}

	providerHandler := func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`{"access_token": "my_auth_token"}`))
		if err != nil {
			panic(err)
		}
	}
	provider := httptest.NewServer(http.HandlerFunc(providerHandler))
	providerURL, err := url.Parse(provider.URL)
	if err != nil {
		return nil, err
	}
	opts.SetProvider(NewTestProvider(providerURL, "mbland@acm.org"))

	return &SignatureTest{
		opts,
		upstreamServer,
		upstreamURL.Host,
		provider,
		make(http.Header),
		httptest.NewRecorder(),
		authenticator,
	}, nil
}

func (st *SignatureTest) Close() {
	st.provider.Close()
	st.upstream.Close()
}

// fakeNetConn simulates an http.Request.Body buffer that will be consumed
// when it is read by the hmacauth.HmacAuth if not handled properly. See:
//   https://github.com/18F/hmacauth/pull/4
type fakeNetConn struct {
	reqBody string
}

func (fnc *fakeNetConn) Read(p []byte) (n int, err error) {
	if bodyLen := len(fnc.reqBody); bodyLen != 0 {
		copy(p, fnc.reqBody)
		fnc.reqBody = ""
		return bodyLen, io.EOF
	}
	return 0, io.EOF
}

func (st *SignatureTest) MakeRequestWithExpectedKey(method, body, key string) error {
	err := validation.Validate(st.opts)
	if err != nil {
		return err
	}
	proxy, err := NewOAuthProxy(st.opts, func(email string) bool { return true })
	if err != nil {
		return err
	}

	var bodyBuf io.ReadCloser
	if body != "" {
		bodyBuf = ioutil.NopCloser(&fakeNetConn{reqBody: body})
	}
	req := httptest.NewRequest(method, "/foo/bar", bodyBuf)
	req.Header = st.header

	state := &sessions.SessionState{
		Email: "mbland@acm.org", AccessToken: "my_access_token"}
	err = proxy.SaveSession(st.rw, req, state)
	if err != nil {
		return err
	}
	for _, c := range st.rw.Result().Cookies() {
		req.AddCookie(c)
	}
	// This is used by the upstream to validate the signature.
	st.authenticator.auth = hmacauth.NewHmacAuth(
		crypto.SHA1, []byte(key), upstream.SignatureHeader, upstream.SignatureHeaders)
	proxy.ServeHTTP(st.rw, req)

	return nil
}

func TestRequestSignature(t *testing.T) {
	testCases := map[string]struct {
		method string
		body   string
		key    string
		resp   string
	}{
		"No request signature": {
			method: "GET",
			body:   "",
			key:    "",
			resp:   "no signature received",
		},
		"Get request": {
			method: "GET",
			body:   "",
			key:    "7d9e1aa87a5954e6f9fc59266b3af9d7c35fda2d",
			resp:   "signatures match",
		},
		"Post request": {
			method: "POST",
			body:   `{ "hello": "world!" }`,
			key:    "d90df39e2d19282840252612dd7c81421a372f61",
			resp:   "signatures match",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			st, err := NewSignatureTest()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(st.Close)
			if tc.key != "" {
				st.opts.SignatureKey = fmt.Sprintf("sha1:%s", tc.key)
			}
			err = st.MakeRequestWithExpectedKey(tc.method, tc.body, tc.key)
			assert.NoError(t, err)
			assert.Equal(t, 200, st.rw.Code)
			assert.Equal(t, tc.resp, st.rw.Body.String())
		})
	}
}

func Test_getAppRedirect(t *testing.T) {
	opts := baseTestOptions()
	opts.WhitelistDomains = append(opts.WhitelistDomains, ".example.com", ".example.com:8443")
	err := validation.Validate(opts)
	assert.NoError(t, err)
	require.NotEmpty(t, opts.ProxyPrefix)
	proxy, err := NewOAuthProxy(opts, func(s string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		url              string
		headers          map[string]string
		reverseProxy     bool
		expectedRedirect string
	}{
		{
			name:             "request outside of ProxyPrefix redirects to original URL",
			url:              "/foo/bar",
			headers:          nil,
			reverseProxy:     false,
			expectedRedirect: "/foo/bar",
		},
		{
			name:             "request with query preserves query",
			url:              "/foo?bar",
			headers:          nil,
			reverseProxy:     false,
			expectedRedirect: "/foo?bar",
		},
		{
			name:             "request under ProxyPrefix redirects to root",
			url:              proxy.ProxyPrefix + "/foo/bar",
			headers:          nil,
			reverseProxy:     false,
			expectedRedirect: "/",
		},
		{
			name: "proxied request outside of ProxyPrefix redirects to proxied URL",
			url:  "https://oauth.example.com/foo/bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   "/foo/bar",
			},
			reverseProxy:     true,
			expectedRedirect: "https://a-service.example.com/foo/bar",
		},
		{
			name: "non-proxied request with spoofed proxy headers wouldn't redirect",
			url:  "https://oauth.example.com/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   "/foo/bar",
			},
			reverseProxy:     false,
			expectedRedirect: "/foo?bar",
		},
		{
			name: "proxied request under ProxyPrefix redirects to root",
			url:  "https://oauth.example.com" + proxy.ProxyPrefix + "/foo/bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   proxy.ProxyPrefix + "/foo/bar",
			},
			reverseProxy:     true,
			expectedRedirect: "https://a-service.example.com/",
		},
		{
			name: "proxied request with port under ProxyPrefix redirects to root",
			url:  "https://oauth.example.com" + proxy.ProxyPrefix + "/foo/bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com:8443",
				"X-Forwarded-Uri":   proxy.ProxyPrefix + "/foo/bar",
			},
			reverseProxy:     true,
			expectedRedirect: "https://a-service.example.com:8443/",
		},
		{
			name: "proxied request with missing uri header would still redirect to desired redirect",
			url:  "https://oauth.example.com/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
			},
			reverseProxy:     true,
			expectedRedirect: "https://a-service.example.com/foo?bar",
		},
		{
			name:             "request with headers proxy not being set (and reverse proxy enabled) would still redirect to desired redirect",
			url:              "https://oauth.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     true,
			expectedRedirect: "/foo?bar",
		},
		{
			name: "proxied request with X-Auth-Request-Redirect being set outside of ProxyPrefix redirects to proxied URL",
			url:  "https://oauth.example.com/foo/bar",
			headers: map[string]string{
				"X-Auth-Request-Redirect": "https://a-service.example.com/foo/bar",
			},
			reverseProxy:     true,
			expectedRedirect: "https://a-service.example.com/foo/bar",
		},
		{
			name:             "proxied request with rd query string redirects to proxied URL",
			url:              "https://oauth.example.com/foo/bar?rd=https%3A%2F%2Fa%2Dservice%2Eexample%2Ecom%2Ffoo%2Fbar",
			headers:          nil,
			reverseProxy:     false,
			expectedRedirect: "https://a-service.example.com/foo/bar",
		},
		{
			name: "proxied request with rd query string and all headers set (and reverse proxy not enabled) redirects to proxied URL on rd query string",
			url:  "https://oauth.example.com/foo/bar?rd=https%3A%2F%2Fa%2Dservice%2Eexample%2Ecom%2Ffoo%2Fjazz",
			headers: map[string]string{
				"X-Auth-Request-Redirect": "https://a-service.example.com/foo/baz",
				"X-Forwarded-Proto":       "http",
				"X-Forwarded-Host":        "another-service.example.com",
				"X-Forwarded-Uri":         "/seasons/greetings",
			},
			reverseProxy:     false,
			expectedRedirect: "https://a-service.example.com/foo/jazz",
		},
		{
			name: "proxied request with rd query string and some headers set redirects to proxied URL on rd query string",
			url:  "https://oauth.example.com/foo/bar?rd=https%3A%2F%2Fa%2Dservice%2Eexample%2Ecom%2Ffoo%2Fbaz",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "another-service.example.com",
				"X-Forwarded-Uri":   "/seasons/greetings",
			},
			reverseProxy:     true,
			expectedRedirect: "https://a-service.example.com/foo/baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			for header, value := range tt.headers {
				if value != "" {
					req.Header.Add(header, value)
				}
			}
			req = middleware.AddRequestScope(req, &middleware.RequestScope{
				ReverseProxy: tt.reverseProxy,
			})
			redirect, err := proxy.getAppRedirect(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedRedirect, redirect)
		})
	}
}

type ajaxRequestTest struct {
	opts  *options.Options
	proxy *OAuthProxy
}

func newAjaxRequestTest() (*ajaxRequestTest, error) {
	test := &ajaxRequestTest{}
	test.opts = baseTestOptions()
	err := validation.Validate(test.opts)
	if err != nil {
		return nil, err
	}

	test.proxy, err = NewOAuthProxy(test.opts, func(email string) bool {
		return true
	})
	if err != nil {
		return nil, err
	}
	return test, nil
}

func (test *ajaxRequestTest) getEndpoint(endpoint string, header http.Header) (int, http.Header, error) {
	rw := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, endpoint, strings.NewReader(""))
	if err != nil {
		return 0, nil, err
	}
	req.Header = header
	test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Header(), nil
}

func testAjaxUnauthorizedRequest(t *testing.T, header http.Header) {
	test, err := newAjaxRequestTest()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/test"

	code, rh, err := test.getEndpoint(endpoint, header)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, code)
	mime := rh.Get("Content-Type")
	assert.Equal(t, applicationJSON, mime)
}
func TestAjaxUnauthorizedRequest1(t *testing.T) {
	header := make(http.Header)
	header.Add("accept", applicationJSON)

	testAjaxUnauthorizedRequest(t, header)
}

func TestAjaxUnauthorizedRequest2(t *testing.T) {
	header := make(http.Header)
	header.Add("Accept", applicationJSON)

	testAjaxUnauthorizedRequest(t, header)
}

func TestAjaxUnauthorizedRequestAccept1(t *testing.T) {
	header := make(http.Header)
	header.Add("Accept", "application/json, text/plain, */*")

	testAjaxUnauthorizedRequest(t, header)
}

func TestAjaxForbiddendRequest(t *testing.T) {
	test, err := newAjaxRequestTest()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/test"
	header := make(http.Header)
	code, rh, err := test.getEndpoint(endpoint, header)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, code)
	mime := rh.Get("Content-Type")
	assert.NotEqual(t, applicationJSON, mime)
}

func TestClearSplitCookie(t *testing.T) {
	opts := baseTestOptions()
	opts.Cookie.Secret = base64CookieSecret
	opts.Cookie.Name = "oauth2"
	opts.Cookie.Domains = []string{"abc"}
	err := validation.Validate(opts)
	assert.NoError(t, err)

	store, err := sessionscookie.NewCookieSessionStore(&opts.Session, &opts.Cookie)
	if err != nil {
		t.Fatal(err)
	}

	p := OAuthProxy{CookieName: opts.Cookie.Name, CookieDomains: opts.Cookie.Domains, sessionStore: store}
	var rw = httptest.NewRecorder()
	req := httptest.NewRequest("get", "/", nil)

	req.AddCookie(&http.Cookie{
		Name:  "test1",
		Value: "test1",
	})
	req.AddCookie(&http.Cookie{
		Name:  "oauth2_0",
		Value: "oauth2_0",
	})
	req.AddCookie(&http.Cookie{
		Name:  "oauth2_1",
		Value: "oauth2_1",
	})

	err = p.ClearSessionCookie(rw, req)
	assert.NoError(t, err)
	header := rw.Header()

	assert.Equal(t, 2, len(header["Set-Cookie"]), "should have 3 set-cookie header entries")
}

func TestClearSingleCookie(t *testing.T) {
	opts := baseTestOptions()
	opts.Cookie.Name = "oauth2"
	opts.Cookie.Domains = []string{"abc"}
	store, err := sessionscookie.NewCookieSessionStore(&opts.Session, &opts.Cookie)
	if err != nil {
		t.Fatal(err)
	}

	p := OAuthProxy{CookieName: opts.Cookie.Name, CookieDomains: opts.Cookie.Domains, sessionStore: store}
	var rw = httptest.NewRecorder()
	req := httptest.NewRequest("get", "/", nil)

	req.AddCookie(&http.Cookie{
		Name:  "test1",
		Value: "test1",
	})
	req.AddCookie(&http.Cookie{
		Name:  "oauth2",
		Value: "oauth2",
	})

	err = p.ClearSessionCookie(rw, req)
	assert.NoError(t, err)
	header := rw.Header()

	assert.Equal(t, 1, len(header["Set-Cookie"]), "should have 1 set-cookie header entries")
}

type NoOpKeySet struct {
}

func (NoOpKeySet) VerifySignature(_ context.Context, jwt string) (payload []byte, err error) {
	splitStrings := strings.Split(jwt, ".")
	payloadString := splitStrings[1]
	return base64.RawURLEncoding.DecodeString(payloadString)
}

func TestGetJwtSession(t *testing.T) {
	/* token payload:
	{
	  "sub": "1234567890",
	  "aud": "https://test.myapp.com",
	  "name": "John Doe",
	  "email": "john@example.com",
	  "iss": "https://issuer.example.com",
	  "iat": 1553691215,
	  "exp": 1912151821
	}
	*/
	goodJwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly90ZXN0Lm15YXBwLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsImVtY" +
		"WlsIjoiam9obkBleGFtcGxlLmNvbSIsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNTUzNjkxMj" +
		"E1LCJleHAiOjE5MTIxNTE4MjF9." +
		"rLVyzOnEldUq_pNkfa-WiV8TVJYWyZCaM2Am_uo8FGg11zD7l-qmz3x1seTvqpH6Y0Ty00fmv6dJnGnC8WMnPXQiodRTfhBSe" +
		"OKZMu0HkMD2sg52zlKkbfLTO6ic5VnbVgwjjrB8am_Ta6w7kyFUaB5C1BsIrrLMldkWEhynbb8"

	keyset := NoOpKeySet{}
	verifier := oidc.NewVerifier("https://issuer.example.com", keyset,
		&oidc.Config{ClientID: "https://test.myapp.com", SkipExpiryCheck: true})

	test, err := NewAuthOnlyEndpointTest("", func(opts *options.Options) {
		opts.InjectRequestHeaders = []options.Header{
			{
				Name: "Authorization",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim:  "id_token",
							Prefix: "Bearer ",
						},
					},
				},
			},
			{
				Name: "X-Forwarded-User",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim: "user",
						},
					},
				},
			},
			{
				Name: "X-Forwarded-Email",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim: "email",
						},
					},
				},
			},
		}

		opts.InjectResponseHeaders = []options.Header{
			{
				Name: "Authorization",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim:  "id_token",
							Prefix: "Bearer ",
						},
					},
				},
			},
			{
				Name: "X-Auth-Request-User",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim: "user",
						},
					},
				},
			},
			{
				Name: "X-Auth-Request-Email",
				Values: []options.HeaderValue{
					{
						ClaimSource: &options.ClaimSource{
							Claim: "email",
						},
					},
				},
			},
		}
		opts.SkipJwtBearerTokens = true
		opts.SetJWTBearerVerifiers(append(opts.GetJWTBearerVerifiers(), verifier))
	})
	if err != nil {
		t.Fatal(err)
	}
	tp, _ := test.proxy.provider.(*TestProvider)
	tp.GroupValidator = func(s string) bool {
		return true
	}

	authHeader := fmt.Sprintf("Bearer %s", goodJwt)
	test.req.Header = map[string][]string{
		"Authorization": {authHeader},
	}

	test.proxy.ServeHTTP(test.rw, test.req)
	if test.rw.Code >= 400 {
		t.Fatalf("expected 3xx got %d", test.rw.Code)
	}

	// Check PassAuthorization, should overwrite Basic header
	assert.Equal(t, test.req.Header.Get("Authorization"), authHeader)
	assert.Equal(t, test.req.Header.Get("X-Forwarded-User"), "1234567890")
	assert.Equal(t, test.req.Header.Get("X-Forwarded-Email"), "john@example.com")

	// SetAuthorization and SetXAuthRequest
	assert.Equal(t, test.rw.Header().Get("Authorization"), authHeader)
	assert.Equal(t, test.rw.Header().Get("X-Auth-Request-User"), "1234567890")
	assert.Equal(t, test.rw.Header().Get("X-Auth-Request-Email"), "john@example.com")
}

func Test_prepareNoCache(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prepareNoCache(w)
	})
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mux.ServeHTTP(rec, req)

	for k, v := range noCacheHeaders {
		assert.Equal(t, rec.Header().Get(k), v)
	}
}

func Test_noCacheHeaders(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("upstream"))
		if err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.UpstreamServers = options.Upstreams{
		{
			ID:   upstreamServer.URL,
			Path: "/",
			URI:  upstreamServer.URL,
		},
	}
	opts.SkipAuthRegex = []string{".*"}
	err := validation.Validate(opts)
	assert.NoError(t, err)
	proxy, err := NewOAuthProxy(opts, func(_ string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	t.Run("not exist in response from upstream", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/upstream", nil)
		proxy.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "upstream", rec.Body.String())

		// checking noCacheHeaders does not exists in response headers from upstream
		for k := range noCacheHeaders {
			assert.Equal(t, "", rec.Header().Get(k))
		}
	})

	t.Run("has no-cache", func(t *testing.T) {
		tests := []struct {
			path       string
			hasNoCache bool
		}{
			{
				path:       "/oauth2/sign_in",
				hasNoCache: true,
			},
			{
				path:       "/oauth2/sign_out",
				hasNoCache: true,
			},
			{
				path:       "/oauth2/start",
				hasNoCache: true,
			},
			{
				path:       "/oauth2/callback",
				hasNoCache: true,
			},
			{
				path:       "/oauth2/auth",
				hasNoCache: false,
			},
			{
				path:       "/oauth2/userinfo",
				hasNoCache: true,
			},
			{
				path:       "/upstream",
				hasNoCache: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.path, func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, tt.path, nil)
				proxy.ServeHTTP(rec, req)
				cacheControl := rec.Result().Header.Get("Cache-Control")
				if tt.hasNoCache != (strings.Contains(cacheControl, "no-cache")) {
					t.Errorf(`unexpected "Cache-Control" header: %s`, cacheControl)
				}
			})
		}

	})
}

func baseTestOptions() *options.Options {
	opts := options.NewOptions()
	opts.Cookie.Secret = rawCookieSecret
	opts.ClientID = clientID
	opts.ClientSecret = clientSecret
	opts.EmailDomains = []string{"*"}

	// Default injected headers for legacy configuration
	opts.InjectRequestHeaders = []options.Header{
		{
			Name: "Authorization",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "user",
						BasicAuthPassword: &options.SecretSource{
							Value: []byte(base64.StdEncoding.EncodeToString([]byte("This is a secure password"))),
						},
					},
				},
			},
		},
		{
			Name: "X-Forwarded-User",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Forwarded-Email",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim: "email",
					},
				},
			},
		},
	}

	return opts
}

func TestTrustedIPs(t *testing.T) {
	tests := []struct {
		name               string
		trustedIPs         []string
		reverseProxy       bool
		realClientIPHeader string
		req                *http.Request
		expectTrusted      bool
	}{
		// Check unconfigured behavior.
		{
			name:               "Default",
			trustedIPs:         nil,
			reverseProxy:       false,
			realClientIPHeader: "X-Real-IP", // Default value
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				return req
			}(),
			expectTrusted: false,
		},
		// Check using req.RemoteAddr (Options.ReverseProxy == false).
		{
			name:               "WithRemoteAddr",
			trustedIPs:         []string{"127.0.0.1"},
			reverseProxy:       false,
			realClientIPHeader: "X-Real-IP", // Default value
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.RemoteAddr = "127.0.0.1:43670"
				return req
			}(),
			expectTrusted: true,
		},
		// Check ignores req.RemoteAddr match when behind a reverse proxy / missing header.
		{
			name:               "IgnoresRemoteAddrInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Real-IP", // Default value
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.RemoteAddr = "127.0.0.1:44324"
				return req
			}(),
			expectTrusted: false,
		},
		// Check successful trusting of localhost in IPv4.
		{
			name:               "TrustsLocalhostInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add("X-Forwarded-For", "127.0.0.1")
				return req
			}(),
			expectTrusted: true,
		},
		// Check successful trusting of localhost in IPv6.
		{
			name:               "TrustsIP6LocalostInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add("X-Forwarded-For", "::1")
				return req
			}(),
			expectTrusted: true,
		},
		// Check does not trust random IPv4 address.
		{
			name:               "DoesNotTrustRandomIP4Address",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add("X-Forwarded-For", "12.34.56.78")
				return req
			}(),
			expectTrusted: false,
		},
		// Check does not trust random IPv6 address.
		{
			name:               "DoesNotTrustRandomIP6Address",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add("X-Forwarded-For", "::2")
				return req
			}(),
			expectTrusted: false,
		},
		// Check respects correct header.
		{
			name:               "RespectsCorrectHeaderInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add("X-Real-IP", "::1")
				return req
			}(),
			expectTrusted: false,
		},
		// Check doesn't trust if garbage is provided.
		{
			name:               "DoesNotTrustGarbageInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Add("X-Forwarded-For", "adsfljk29242as!!")
				return req
			}(),
			expectTrusted: false,
		},
		// Check doesn't trust if garbage is provided (no reverse-proxy).
		{
			name:               "DoesNotTrustGarbage",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       false,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.RemoteAddr = "adsfljk29242as!!"
				return req
			}(),
			expectTrusted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseTestOptions()
			opts.UpstreamServers = options.Upstreams{
				{
					ID:     "static",
					Path:   "/",
					Static: true,
				},
			}
			opts.TrustedIPs = tt.trustedIPs
			opts.ReverseProxy = tt.reverseProxy
			opts.RealClientIPHeader = tt.realClientIPHeader
			err := validation.Validate(opts)
			assert.NoError(t, err)

			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			assert.NoError(t, err)
			rw := httptest.NewRecorder()

			proxy.ServeHTTP(rw, tt.req)
			if tt.expectTrusted {
				assert.Equal(t, 200, rw.Code)
			} else {
				assert.Equal(t, 403, rw.Code)
			}
		})
	}
}

func Test_buildRoutesAllowlist(t *testing.T) {
	type expectedAllowedRoute struct {
		method      string
		regexString string
	}

	testCases := []struct {
		name           string
		skipAuthRegex  []string
		skipAuthRoutes []string
		expectedRoutes []expectedAllowedRoute
		shouldError    bool
	}{
		{
			name:           "No skip auth configured",
			skipAuthRegex:  []string{},
			skipAuthRoutes: []string{},
			expectedRoutes: []expectedAllowedRoute{},
			shouldError:    false,
		},
		{
			name: "Only skipAuthRegex configured",
			skipAuthRegex: []string{
				"^/foo/bar",
				"^/baz/[0-9]+/thing",
			},
			skipAuthRoutes: []string{},
			expectedRoutes: []expectedAllowedRoute{
				{
					method:      "",
					regexString: "^/foo/bar",
				},
				{
					method:      "",
					regexString: "^/baz/[0-9]+/thing",
				},
			},
			shouldError: false,
		},
		{
			name:          "Only skipAuthRoutes configured",
			skipAuthRegex: []string{},
			skipAuthRoutes: []string{
				"GET=^/foo/bar",
				"POST=^/baz/[0-9]+/thing",
				"^/all/methods$",
				"WEIRD=^/methods/are/allowed",
				"PATCH=/second/equals?are=handled&just=fine",
			},
			expectedRoutes: []expectedAllowedRoute{
				{
					method:      "GET",
					regexString: "^/foo/bar",
				},
				{
					method:      "POST",
					regexString: "^/baz/[0-9]+/thing",
				},
				{
					method:      "",
					regexString: "^/all/methods$",
				},
				{
					method:      "WEIRD",
					regexString: "^/methods/are/allowed",
				},
				{
					method:      "PATCH",
					regexString: "/second/equals?are=handled&just=fine",
				},
			},
			shouldError: false,
		},
		{
			name: "Both skipAuthRegexes and skipAuthRoutes configured",
			skipAuthRegex: []string{
				"^/foo/bar/regex",
				"^/baz/[0-9]+/thing/regex",
			},
			skipAuthRoutes: []string{
				"GET=^/foo/bar",
				"POST=^/baz/[0-9]+/thing",
				"^/all/methods$",
			},
			expectedRoutes: []expectedAllowedRoute{
				{
					method:      "",
					regexString: "^/foo/bar/regex",
				},
				{
					method:      "",
					regexString: "^/baz/[0-9]+/thing/regex",
				},
				{
					method:      "GET",
					regexString: "^/foo/bar",
				},
				{
					method:      "POST",
					regexString: "^/baz/[0-9]+/thing",
				},
				{
					method:      "",
					regexString: "^/all/methods$",
				},
			},
			shouldError: false,
		},
		{
			name: "Invalid skipAuthRegex entry",
			skipAuthRegex: []string{
				"^/foo/bar",
				"^/baz/[0-9]+/thing",
				"(bad[regex",
			},
			skipAuthRoutes: []string{},
			expectedRoutes: []expectedAllowedRoute{},
			shouldError:    true,
		},
		{
			name:          "Invalid skipAuthRoutes entry",
			skipAuthRegex: []string{},
			skipAuthRoutes: []string{
				"GET=^/foo/bar",
				"POST=^/baz/[0-9]+/thing",
				"^/all/methods$",
				"PUT=(bad[regex",
			},
			expectedRoutes: []expectedAllowedRoute{},
			shouldError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &options.Options{
				SkipAuthRegex:  tc.skipAuthRegex,
				SkipAuthRoutes: tc.skipAuthRoutes,
			}
			routes, err := buildRoutesAllowlist(opts)
			if tc.shouldError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			for i, route := range routes {
				assert.Greater(t, len(tc.expectedRoutes), i)
				assert.Equal(t, route.method, tc.expectedRoutes[i].method)
				assert.Equal(t, route.pathRegex.String(), tc.expectedRoutes[i].regexString)
			}
		})
	}
}

func TestAllowedRequest(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("Allowed Request"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.UpstreamServers = options.Upstreams{
		{
			ID:   upstreamServer.URL,
			Path: "/",
			URI:  upstreamServer.URL,
		},
	}
	opts.SkipAuthRegex = []string{
		"^/skip/auth/regex$",
	}
	opts.SkipAuthRoutes = []string{
		"GET=^/skip/auth/routes/get",
	}
	err := validation.Validate(opts)
	assert.NoError(t, err)
	proxy, err := NewOAuthProxy(opts, func(_ string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		method  string
		url     string
		allowed bool
	}{
		{
			name:    "Regex GET allowed",
			method:  "GET",
			url:     "/skip/auth/regex",
			allowed: true,
		},
		{
			name:    "Regex POST allowed ",
			method:  "POST",
			url:     "/skip/auth/regex",
			allowed: true,
		},
		{
			name:    "Regex denied",
			method:  "GET",
			url:     "/wrong/denied",
			allowed: false,
		},
		{
			name:    "Route allowed",
			method:  "GET",
			url:     "/skip/auth/routes/get",
			allowed: true,
		},
		{
			name:    "Route denied with wrong method",
			method:  "PATCH",
			url:     "/skip/auth/routes/get",
			allowed: false,
		},
		{
			name:    "Route denied with wrong path",
			method:  "GET",
			url:     "/skip/auth/routes/wrong/path",
			allowed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.url, nil)
			assert.NoError(t, err)
			assert.Equal(t, tc.allowed, proxy.isAllowedRoute(req))

			rw := httptest.NewRecorder()
			proxy.ServeHTTP(rw, req)

			if tc.allowed {
				assert.Equal(t, 200, rw.Code)
				assert.Equal(t, "Allowed Request", rw.Body.String())
			} else {
				assert.Equal(t, 403, rw.Code)
			}
		})
	}
}

func TestProxyAllowedGroups(t *testing.T) {
	tests := []struct {
		name               string
		allowedGroups      []string
		groups             []string
		expectUnauthorized bool
	}{
		{"NoAllowedGroups", []string{}, []string{}, false},
		{"NoAllowedGroupsUserHasGroups", []string{}, []string{"a", "b"}, false},
		{"UserInAllowedGroup", []string{"a"}, []string{"a", "b"}, false},
		{"UserNotInAllowedGroup", []string{"a"}, []string{"c"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emailAddress := "test"
			created := time.Now()

			session := &sessions.SessionState{
				Groups:      tt.groups,
				Email:       emailAddress,
				AccessToken: "oauth_token",
				CreatedAt:   &created,
			}

			upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			}))
			t.Cleanup(upstreamServer.Close)

			test, err := NewProcessCookieTestWithOptionsModifiers(func(opts *options.Options) {
				opts.AllowedGroups = tt.allowedGroups
				opts.UpstreamServers = options.Upstreams{
					{
						ID:   upstreamServer.URL,
						Path: "/",
						URI:  upstreamServer.URL,
					},
				}
			})
			if err != nil {
				t.Fatal(err)
			}

			test.req, _ = http.NewRequest("GET", "/", nil)

			test.req.Header.Add("accept", applicationJSON)
			err = test.SaveSession(session)
			assert.NoError(t, err)
			test.proxy.ServeHTTP(test.rw, test.req)

			if tt.expectUnauthorized {
				assert.Equal(t, http.StatusForbidden, test.rw.Code)
			} else {
				assert.Equal(t, http.StatusOK, test.rw.Code)
			}
		})
	}
}

func TestAuthOnlyAllowedGroups(t *testing.T) {
	testCases := []struct {
		name               string
		allowedGroups      []string
		groups             []string
		querystring        string
		expectedStatusCode int
	}{
		{
			name:               "NoAllowedGroups",
			allowedGroups:      []string{},
			groups:             []string{},
			querystring:        "",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "NoAllowedGroupsUserHasGroups",
			allowedGroups:      []string{},
			groups:             []string{"a", "b"},
			querystring:        "",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInAllowedGroup",
			allowedGroups:      []string{"a"},
			groups:             []string{"a", "b"},
			querystring:        "",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserNotInAllowedGroup",
			allowedGroups:      []string{"a"},
			groups:             []string{"c"},
			querystring:        "",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "UserInQuerystringGroup",
			allowedGroups:      []string{"a", "b"},
			groups:             []string{"a", "c"},
			querystring:        "?allowed_groups=a",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInMultiParamQuerystringGroup",
			allowedGroups:      []string{"a", "b"},
			groups:             []string{"b"},
			querystring:        "?allowed_groups=a&allowed_groups=b,d",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInOnlyQuerystringGroup",
			allowedGroups:      []string{},
			groups:             []string{"a", "c"},
			querystring:        "?allowed_groups=a,b",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInDelimitedQuerystringGroup",
			allowedGroups:      []string{"a", "b", "c"},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=a,c",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserNotInQuerystringGroup",
			allowedGroups:      []string{},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=a,b",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserInConfigGroupNotInQuerystringGroup",
			allowedGroups:      []string{"a", "b", "c"},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=a,b",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserInQuerystringGroupNotInConfigGroup",
			allowedGroups:      []string{"a", "b"},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=b,c",
			expectedStatusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			emailAddress := "test"
			created := time.Now()

			session := &sessions.SessionState{
				Groups:      tc.groups,
				Email:       emailAddress,
				AccessToken: "oauth_token",
				CreatedAt:   &created,
			}

			test, err := NewAuthOnlyEndpointTest(tc.querystring, func(opts *options.Options) {
				opts.AllowedGroups = tc.allowedGroups
			})
			if err != nil {
				t.Fatal(err)
			}

			err = test.SaveSession(session)
			assert.NoError(t, err)

			test.proxy.ServeHTTP(test.rw, test.req)

			assert.Equal(t, tc.expectedStatusCode, test.rw.Code)
		})
	}
}
