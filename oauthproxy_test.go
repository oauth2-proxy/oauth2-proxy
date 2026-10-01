package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	sessionscookie "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/upstream"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/onsi/ginkgo/v2"
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
	req, _ := http.NewRequest(http.MethodGet, "/robots.txt", nil)
	proxy.ServeHTTP(rw, req)
	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "User-agent: *\nDisallow: /\n", rw.Body.String())
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
	_, err = proxy.redeemCode(req, "")
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

			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			proxy.provider = NewTestProvider(&url.URL{Host: "www.example.com"}, providerEmail)

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
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   providerServer.URL,
				Path: "/",
				URI:  providerServer.URL,
			},
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

	proxy, err := NewOAuthProxy(opts, func(email string) bool {
		return email == emailAddress
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy.provider = NewTestProvider(providerURL, emailAddress)

	// Save the required session
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	err = proxy.sessionStore.Save(rw, req, &sessions.SessionState{
		Email: emailAddress,
	})
	assert.NoError(t, err)

	// Extract the cookie value to inject into the test request
	cookie := rw.Header().Values("Set-Cookie")[0]

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
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
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	err = proxy.sessionStore.Save(rw, req, session)
	assert.NoError(t, err)

	// Extract the cookie value to inject into the test request
	cookie := rw.Header().Values("Set-Cookie")[0]

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
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
	ValidToken      bool
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
	patt.opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   patt.providerServer.URL,
				Path: "/",
				URI:  patt.providerServer.URL,
			},
		},
	}
	if opts.ProxyUpstream.ID != "" {
		patt.opts.UpstreamServers.Upstreams = append(patt.opts.UpstreamServers.Upstreams, opts.ProxyUpstream)
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

	testProvider := NewTestProvider(providerURL, emailAddress)
	testProvider.ValidToken = opts.ValidToken
	patt.proxy, err = NewOAuthProxy(patt.opts, func(email string) bool {
		return email == emailAddress
	})
	patt.proxy.provider = testProvider
	if err != nil {
		return nil, err
	}
	return patt, nil
}

func (patTest *PassAccessTokenTest) Close() {
	patTest.providerServer.Close()
}

func (patTest *PassAccessTokenTest) getCallbackEndpoint() (httpCode int, cookie string) {
	rw := httptest.NewRecorder()

	csrf, err := cookies.NewCSRF(patTest.proxy.CookieOptions, "")
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf(
			"/oauth2/callback?code=callback_code&state=%s",
			encodeState(csrf.HashOAuthState(), "%2F", false),
		),
		strings.NewReader(""),
	)
	if err != nil {
		return 0, ""
	}

	// rw is a dummy here, we just want the csrfCookie to add to our req
	csrfCookie, err := csrf.SetCookie(httptest.NewRecorder(), req)
	if err != nil {
		panic(err)
	}
	req.AddCookie(csrfCookie)

	patTest.proxy.ServeHTTP(rw, req)

	if len(rw.Header().Values("Set-Cookie")) >= 2 {
		cookie = rw.Header().Values("Set-Cookie")[1]
	}

	return rw.Code, cookie
}

func TestOAuthCallbackCSRFCookieLogging(t *testing.T) {
	opts := baseTestOptions()
	require.NoError(t, validation.Validate(opts))
	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	require.NoError(t, err)

	csrf, err := cookies.NewCSRF(proxy.CookieOptions, "synthetic-pkce-verifier")
	require.NoError(t, err)
	csrfCookie, err := csrf.SetCookie(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, err)
	secret, err := proxy.CookieOptions.GetSecret()
	require.NoError(t, err)
	value, _, valid := encryption.Validate(csrfCookie, secret, proxy.CookieOptions.CSRFExpire)
	require.True(t, valid)
	expiredValue, err := encryption.SignedValue(secret, csrfCookie.Name, value, time.Now().Add(-proxy.CookieOptions.CSRFExpire-time.Hour))
	require.NoError(t, err)

	sessionCookie := &http.Cookie{Name: proxy.CookieOptions.Name, Value: "synthetic-session-credential"}
	invalidCookie := &http.Cookie{Name: csrfCookie.Name, Value: "synthetic-invalid-csrf-credential"}
	expiredCookie := &http.Cookie{Name: csrfCookie.Name, Value: expiredValue}
	otherCookie := &http.Cookie{Name: "_other_csrf", Value: "synthetic-other-csrf-credential"}
	testCases := []struct {
		name       string
		cookies    []*http.Cookie
		diagnostic string
	}{
		{
			name:       "no cookies",
			diagnostic: "No cookies were found in OAuth callback.",
		},
		{
			name:       "missing CSRF cookie",
			cookies:    []*http.Cookie{sessionCookie},
			diagnostic: "Cookies were found in OAuth callback, but none was a CSRF cookie.",
		},
		{
			name:       "invalid expected CSRF cookie",
			cookies:    []*http.Cookie{sessionCookie, invalidCookie},
			diagnostic: fmt.Sprintf("CSRF cookie %s was found in OAuth callback.", csrfCookie.Name),
		},
		{
			name:       "expired expected CSRF cookie",
			cookies:    []*http.Cookie{sessionCookie, expiredCookie},
			diagnostic: fmt.Sprintf("CSRF cookie %s was found in OAuth callback.", csrfCookie.Name),
		},
		{
			name:       "other CSRF cookie",
			cookies:    []*http.Cookie{sessionCookie, otherCookie},
			diagnostic: fmt.Sprintf("CSRF cookie %s was found in OAuth callback, but it is not the expected one (%s).", otherCookie.Name, csrfCookie.Name),
		},
	}
	loggingCases := []struct {
		name     string
		standard bool
		auth     bool
		request  bool
	}{
		{name: "all enabled", standard: true, auth: true, request: true},
		{name: "auth disabled", standard: true, request: true},
		{name: "only auth enabled", auth: true},
		{name: "all disabled"},
	}
	for _, tc := range testCases {
		for _, logging := range loggingCases {
			for _, authScheme := range []string{"Basic", "Bearer"} {
				t.Run(tc.name+"/"+logging.name+"/"+authScheme, func(t *testing.T) {
					var output, errors bytes.Buffer
					logger.SetOutput(&output)
					logger.SetErrOutput(&errors)
					logger.SetStandardEnabled(logging.standard)
					logger.SetAuthEnabled(logging.auth)
					logger.SetReqEnabled(logging.request)
					logger.SetAuthTemplate("AUTH {{.RequestID}} {{.Username}} {{.Status}} {{.Message}}")
					logger.SetReqTemplate("REQUEST " + logger.DefaultRequestLoggingFormat)
					t.Cleanup(func() {
						logger.SetOutput(ginkgo.GinkgoWriter)
						logger.SetErrOutput(ginkgo.GinkgoWriter)
						logger.SetStandardEnabled(true)
						logger.SetAuthEnabled(true)
						logger.SetReqEnabled(true)
						logger.SetAuthTemplate(logger.DefaultAuthLoggingFormat)
						logger.SetReqTemplate(logger.DefaultRequestLoggingFormat)
					})

					query := url.Values{
						"code":  {"synthetic-callback-code"},
						"state": {encodeState(csrf.HashOAuthState(), "/", false)},
					}
					req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+query.Encode(), nil)
					req.Header.Set("X-Request-Id", "callback-log-test")
					credential := "synthetic-bearer-credential"
					if authScheme == "Basic" {
						credential = base64.StdEncoding.EncodeToString([]byte("synthetic-user:synthetic-password"))
					}
					req.Header.Set("Authorization", authScheme+" "+credential)
					req.Header.Set("X-Synthetic-Secret", "synthetic-header-credential")
					for _, cookie := range tc.cookies {
						req.AddCookie(cookie)
					}

					rw := httptest.NewRecorder()
					proxy.ServeHTTP(rw, req)

					assert.Equal(t, http.StatusForbidden, rw.Code)
					assert.Contains(t, rw.Body.String(), "Unable to find a valid CSRF token")
					assert.Empty(t, rw.Result().Cookies())
					assert.Empty(t, errors.String())
					logs := output.String() + errors.String()
					assert.NotContains(t, logs, credential)
					assert.NotContains(t, logs, "synthetic-header-credential")
					for _, cookie := range tc.cookies {
						assert.NotContains(t, logs, cookie.Value)
					}
					expectedAuth := "AUTH callback-log-test - AuthFailure " + tc.diagnostic + "\n" +
						fmt.Sprintf("AUTH callback-log-test - AuthFailure Invalid authentication via OAuth2: unable to obtain CSRF cookie: CSRF cookie with name '%s' was not found\n", csrfCookie.Name)
					if !logging.auth {
						expectedAuth = ""
					}
					if logging.request {
						assert.True(t, strings.HasPrefix(output.String(), expectedAuth+"REQUEST "), "unexpected logs: %s", output.String())
						assert.Equal(t, strings.Count(expectedAuth, "\n")+1, strings.Count(output.String(), "\n"))
					} else {
						assert.Equal(t, expectedAuth, output.String())
					}
				})
			}
		}
	}
}

type failingSaveSessionStore struct {
	sessions.SessionStore
}

func (failingSaveSessionStore) Save(http.ResponseWriter, *http.Request, *sessions.SessionState) error {
	return errors.New("session save failed")
}

func TestOAuthCallbackClientIPLogging(t *testing.T) {
	test, err := NewPassAccessTokenTest(PassAccessTokenTestOptions{ValidToken: true})
	require.NoError(t, err)
	t.Cleanup(test.Close)
	t.Cleanup(func() { logger.SetErrOutput(ginkgo.GinkgoWriter) })
	test.proxy.sessionStore = failingSaveSessionStore{test.proxy.sessionStore}
	test.proxy.realClientIPParser, err = ip.GetRealClientIPParser("X-Forwarded-For")
	require.NoError(t, err)
	trustedProxies, err := ip.ParseNetSet([]string{"192.0.2.0/24"})
	require.NoError(t, err)

	for _, tc := range []struct {
		name         string
		remoteAddr   string
		headerValues []string
		expected     string
	}{
		{"Untrusted peer", "198.51.100.23:1234", []string{"10.0.0.5"}, "198.51.100.23"},
		{"Appending trusted proxy", "192.0.2.10:1234", []string{"10.0.0.5", "198.51.100.23, 192.0.2.20"}, "192.0.2.10 (198.51.100.23)"},
		{"Malformed relevant hop", "192.0.2.10:1234", []string{"10.0.0.5, invalid, 192.0.2.20"}, "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			csrf, err := cookies.NewCSRF(test.proxy.CookieOptions, "")
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=callback_code&state="+encodeState(csrf.HashOAuthState(), "%2F", false), nil)
			req.RemoteAddr = tc.remoteAddr
			for _, value := range tc.headerValues {
				req.Header.Add("X-Forwarded-For", value)
			}
			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
				ReverseProxy:   true,
				TrustedProxies: trustedProxies,
			})
			csrfCookie, err := csrf.SetCookie(httptest.NewRecorder(), req)
			require.NoError(t, err)
			req.AddCookie(csrfCookie)
			var output bytes.Buffer
			logger.SetErrOutput(&output)
			rw := httptest.NewRecorder()
			test.proxy.OAuthCallback(rw, req)
			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, output.String(), "Error saving session state for "+tc.expected+": session save failed")
			assert.NotContains(t, output.String(), "10.0.0.5")
		})
	}
}

// getEndpointWithCookie makes a requests againt the oauthproxy with passed requestPath
// and cookie and returns body and status code.
func (patTest *PassAccessTokenTest) getEndpointWithCookie(cookie string, endpoint string) (httpCode int, accessToken string) {
	cookieName := patTest.proxy.CookieOptions.Name
	var value string
	keyPrefix := cookieName + "="

	for _, field := range strings.Split(cookie, "; ") {
		value = strings.TrimPrefix(field, keyPrefix)
		if value != field {
			break
		}
		value = ""
	}
	if value == "" {
		return 0, ""
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, strings.NewReader(""))
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
		ValidToken:      true,
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
		ValidToken:      true,
		ProxyUpstream: options.Upstream{
			ID:     "static-proxy",
			Path:   "/static-proxy",
			Static: ptr.To(true),
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
		ValidToken:      true,
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

func TestSessionValidationFailure(t *testing.T) {
	patTest, err := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		ValidToken: false,
	})
	require.NoError(t, err)
	t.Cleanup(patTest.Close)

	// An unsuccessful validation will return 403 and not set the auth cookie.
	code, cookie := patTest.getCallbackEndpoint()
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "", cookie)
}

type SignInPageTest struct {
	opts                 *options.Options
	proxy                *OAuthProxy
	signInRegexp         *regexp.Regexp
	signInProviderRegexp *regexp.Regexp
}

const (
	signInRedirectPattern = `<input type="hidden" name="rd" value="(.*)">`
	signInSkipProvider    = `>Found<`
	patternNotFound       = "Did not find pattern in body: "
)

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
	req, _ := http.NewRequest(http.MethodGet, endpoint, strings.NewReader(""))
	sipTest.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

type AlwaysSuccessfulValidator struct {
}

func (AlwaysSuccessfulValidator) Validate(_, _ string) bool {
	return true
}

func TestManualSignInStoresUserGroupsInTheSession(t *testing.T) {
	userGroups := []string{"somegroup", "someothergroup"}

	opts := baseTestOptions()
	opts.HtpasswdUserGroups = userGroups
	err := validation.Validate(opts)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := NewOAuthProxy(opts, func(email string) bool {
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy.basicAuthValidator = AlwaysSuccessfulValidator{}

	rw := httptest.NewRecorder()
	formData := url.Values{}
	formData.Set("username", "someuser")
	formData.Set("password", "somepass")
	signInReq, _ := http.NewRequest(http.MethodPost, "/oauth2/sign_in", strings.NewReader(formData.Encode()))
	signInReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	proxy.ServeHTTP(rw, signInReq)

	assert.Equal(t, http.StatusFound, rw.Code)

	req, _ := http.NewRequest(http.MethodGet, "/something", strings.NewReader(formData.Encode()))
	for _, c := range rw.Result().Cookies() {
		req.AddCookie(c)
	}

	s, err := proxy.sessionStore.Load(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, userGroups, s.Groups)
}

type ManualSignInValidator struct{}

func (ManualSignInValidator) Validate(user, password string) bool {
	switch {
	case user == "admin" && password == "adminPass":
		return true
	default:
		return false
	}
}

func ManualSignInWithCredentials(t *testing.T, user, pass string) int {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := NewOAuthProxy(opts, func(email string) bool {
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	proxy.basicAuthValidator = ManualSignInValidator{}

	rw := httptest.NewRecorder()
	formData := url.Values{}
	formData.Set("username", user)
	formData.Set("password", pass)
	signInReq, _ := http.NewRequest(http.MethodPost, "/oauth2/sign_in", strings.NewReader(formData.Encode()))
	signInReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	proxy.ServeHTTP(rw, signInReq)

	return rw.Code
}

func TestManualSignInEmptyUsernameAlert(t *testing.T) {
	statusCode := ManualSignInWithCredentials(t, "", "")
	assert.Equal(t, http.StatusBadRequest, statusCode)
}

func TestManualSignInInvalidCredentialsAlert(t *testing.T) {
	statusCode := ManualSignInWithCredentials(t, "admin", "")
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestManualSignInCorrectCredentials(t *testing.T) {
	statusCode := ManualSignInWithCredentials(t, "admin", "adminPass")
	assert.Equal(t, http.StatusFound, statusCode)
}

func TestSignInPageClearsExistingSessionCookie(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	require.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(string) bool {
		return true
	})
	require.NoError(t, err)

	// Create a real session cookie using the actual session store.
	saveRW := httptest.NewRecorder()
	saveReq := httptest.NewRequest(http.MethodGet, "/", nil)
	err = proxy.sessionStore.Save(saveRW, saveReq, &sessions.SessionState{
		Email: "john.doe@example.com",
	})
	require.NoError(t, err)

	cookies := saveRW.Result().Cookies()
	require.NotEmpty(t, cookies)

	// Send that cookie to the sign-in page.
	req := httptest.NewRequest(http.MethodGet, "/oauth2/sign_in", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rw := httptest.NewRecorder()
	proxy.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)

	cleared := false
	for _, c := range rw.Result().Cookies() {
		if c.Name == proxy.CookieOptions.Name {
			cleared = true
			assert.Equal(t, "", c.Value)
			assert.Less(t, c.MaxAge, 0)
		}
	}

	assert.True(t, cleared, "expected sign-in page to clear existing session cookie")
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
		t.Fatal(patternNotFound +
			signInRedirectPattern + "\nBody:\n" + body)
	}
	if match[1] != endpoint {
		t.Fatal(`expected redirect to "` + endpoint +
			`", but was "` + match[1] + `"`)
	}
}

func TestSignInPageInvalidQueryStringReturnsBadRequest(t *testing.T) {
	sipTest, err := NewSignInPageTest(true)
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "/?q=%va"

	code, _ := sipTest.GetEndpoint(endpoint)
	assert.Equal(t, 400, code)
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
		t.Fatal(patternNotFound +
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
		t.Fatal(patternNotFound +
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
		t.Fatal(patternNotFound +
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
	testProvider := &TestProvider{
		ProviderData: &providers.ProviderData{},
		ValidToken:   opts.providerValidateCookieResponse,
	}

	groups := pcTest.opts.Providers[0].AllowedGroups
	testProvider.ProviderData.AllowedGroups = make(map[string]struct{}, len(groups))
	for _, group := range groups {
		testProvider.ProviderData.AllowedGroups[group] = struct{}{}
	}
	pcTest.proxy.provider = testProvider

	// Now, zero-out proxy.CookieRefresh for the cases that don't involve
	// access_token validation.
	pcTest.proxy.CookieOptions.Refresh = time.Duration(0)
	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest(http.MethodGet, "/", strings.NewReader(""))
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

	pcTest.proxy.CookieOptions.Refresh = time.Hour
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
	pcTest.req, _ = http.NewRequest(http.MethodGet,
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
		{
			name: "With Additional Claim",
			session: &sessions.SessionState{
				User:              "john.doe",
				PreferredUsername: "john",
				Email:             "john.doe@example.com",
				Groups:            []string{"example", "groups"},
				AccessToken:       "my_access_token",
				AdditionalClaims: map[string]interface{}{
					"foo": "bar",
				},
			},
			expectedResponse: "{\"user\":\"john.doe\",\"email\":\"john.doe@example.com\",\"groups\":[\"example\",\"groups\"],\"preferredUsername\":\"john\",\"additionalClaims\":{\"foo\":\"bar\"}}\n",
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
			bodyBytes, _ := io.ReadAll(test.rw.Body)
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

func TestEncodedUrlsStayEncoded(t *testing.T) {
	encodeTest, err := NewSignInPageTest(false)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := encodeTest.GetEndpoint("/%2F/test1/%2F/test2")
	assert.Equal(t, 403, code)
}

func NewAuthOnlyEndpointTest(querystring string, modifiers ...OptionsModifier) (*ProcessCookieTest, error) {
	pcTest, err := NewProcessCookieTestWithOptionsModifiers(modifiers...)
	if err != nil {
		return nil, err
	}
	pcTest.req, _ = http.NewRequest(
		http.MethodGet,
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
	bodyBytes, _ := io.ReadAll(test.rw.Body)
	assert.Equal(t, "", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnNoCookieSetError(t *testing.T) {
	test, err := NewAuthOnlyEndpointTest("")
	if err != nil {
		t.Fatal(err)
	}

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := io.ReadAll(test.rw.Body)
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
	bodyBytes, _ := io.ReadAll(test.rw.Body)
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
	bodyBytes, _ := io.ReadAll(test.rw.Body)
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
	pcTest.opts.Providers[0].AllowedGroups = []string{"oauth_groups"}
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
	pcTest.req, _ = http.NewRequest(http.MethodGet,
		pcTest.opts.ProxyPrefix+authOnlyPath, nil)

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
	pcTest.req, _ = http.NewRequest(http.MethodGet,
		pcTest.opts.ProxyPrefix+authOnlyPath, nil)

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
	pcTest.req, _ = http.NewRequest(http.MethodGet,
		pcTest.opts.ProxyPrefix+authOnlyPath, nil)

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
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
		},
	}
	opts.SkipAuthPreflight = true
	err := validation.Validate(opts)
	assert.NoError(t, err)

	upstreamURL, _ := url.Parse(upstreamServer.URL)

	proxy, err := NewOAuthProxy(opts, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	proxy.provider = NewTestProvider(upstreamURL, "")
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/preflight-request", nil)
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
	authProvider  providers.Provider
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
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
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
	testProvider := NewTestProvider(providerURL, "mbland@acm.org")

	return &SignatureTest{
		opts,
		upstreamServer,
		upstreamURL.Host,
		provider,
		make(http.Header),
		httptest.NewRecorder(),
		authenticator,
		testProvider,
	}, nil
}

func (st *SignatureTest) Close() {
	st.provider.Close()
	st.upstream.Close()
}

// fakeNetConn simulates an http.Request.Body buffer that will be consumed
// when it is read by the hmacauth.HmacAuth if not handled properly. See:
//
//	https://github.com/18F/hmacauth/pull/4
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
	proxy.provider = st.authProvider

	var bodyBuf io.ReadCloser
	if body != "" {
		bodyBuf = io.NopCloser(&fakeNetConn{reqBody: body})
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
			method: http.MethodGet,
			body:   "",
			key:    "",
			resp:   "no signature received",
		},
		"Get request": {
			method: http.MethodGet,
			body:   "",
			key:    "7d9e1aa87a5954e6f9fc59266b3af9d7c35fda2d",
			resp:   "signatures match",
		},
		"Post request": {
			method: http.MethodPost,
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

type ajaxRequestTest struct {
	opts  *options.Options
	proxy *OAuthProxy
}

func newAjaxRequestTest(forceJSONErrors bool) (*ajaxRequestTest, error) {
	test := &ajaxRequestTest{}
	test.opts = baseTestOptions()
	test.opts.ForceJSONErrors = forceJSONErrors
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

func (test *ajaxRequestTest) getEndpoint(endpoint string, header http.Header) (int, http.Header, []byte, error) {
	rw := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, endpoint, strings.NewReader(""))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header = header
	test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Header(), rw.Body.Bytes(), nil
}

func testAjaxUnauthorizedRequest(t *testing.T, header http.Header, forceJSONErrors bool) {
	test, err := newAjaxRequestTest(forceJSONErrors)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/test"

	code, rh, body, err := test.getEndpoint(endpoint, header)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, code)
	mime := rh.Get("Content-Type")
	assert.Equal(t, applicationJSON, mime)
	assert.Equal(t, []byte("{}"), body)
}
func TestAjaxUnauthorizedRequest1(t *testing.T) {
	header := make(http.Header)
	header.Add("accept", applicationJSON)

	testAjaxUnauthorizedRequest(t, header, false)
}

func TestAjaxUnauthorizedRequest2(t *testing.T) {
	header := make(http.Header)
	header.Add("Accept", applicationJSON)

	testAjaxUnauthorizedRequest(t, header, false)
}

func TestAjaxUnauthorizedRequestAccept1(t *testing.T) {
	header := make(http.Header)
	header.Add("Accept", "application/json, text/plain, */*")

	testAjaxUnauthorizedRequest(t, header, false)
}

func TestForceJSONErrorsUnauthorizedRequest(t *testing.T) {
	testAjaxUnauthorizedRequest(t, nil, true)
}

func TestAjaxForbiddendRequest(t *testing.T) {
	test, err := newAjaxRequestTest(false)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/test"
	header := make(http.Header)
	code, rh, _, err := test.getEndpoint(endpoint, header)
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

	p := OAuthProxy{CookieOptions: &opts.Cookie, sessionStore: store}
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

	p := OAuthProxy{CookieOptions: &opts.Cookie, sessionStore: store}
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
		&oidc.Config{ClientID: "https://test.myapp.com", SkipExpiryCheck: true,
			SkipClientIDCheck: true})
	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: []string{"aud"},
		ClientID:       "https://test.myapp.com",
		ExtraAudiences: []string{},
	}
	internalVerifier := internaloidc.NewVerifier(verifier, verificationOptions)

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
		opts.SetJWTBearerVerifiers(append(opts.GetJWTBearerVerifiers(), internalVerifier))
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
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
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
				path:       "/oauth2/refresh",
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

func TestSignOutCallsBackendLogoutURL(t *testing.T) {
	const testIDToken = "test-id-token-12345"
	var receivedURL string
	backendLogoutServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedURL = req.URL.String()
		rw.WriteHeader(http.StatusOK)
	}))
	defer backendLogoutServer.Close()

	opts := baseTestOptions()
	opts.Providers[0].BackendLogoutURL = backendLogoutServer.URL + "/logout?id_token_hint={id_token}"
	err := validation.Validate(opts)
	require.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	require.NoError(t, err)

	// Save a session with IDToken so backend logout can use it
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err = proxy.sessionStore.Save(rw, req, &sessions.SessionState{
		Email:   "user@example.com",
		IDToken: testIDToken,
	})
	require.NoError(t, err)
	cookie := rw.Header().Values("Set-Cookie")[0]

	// Hit sign_out with the session cookie; backend logout should be called before session is cleared
	signOutReq := httptest.NewRequest(http.MethodGet, "/oauth2/sign_out", nil)
	signOutReq.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, signOutReq)

	assert.Equal(t, http.StatusFound, rec.Code, "sign_out should redirect")
	assert.Contains(t, receivedURL, "id_token_hint="+testIDToken,
		"backend logout URL should have been called with id_token from session")
}

func baseTestOptions() *options.Options {
	opts := options.NewOptions()
	opts.Cookie.Secret = rawCookieSecret
	opts.Providers[0].ID = "providerID"
	opts.Providers[0].ClientID = clientID
	opts.Providers[0].ClientSecret = clientSecret
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
	xffRequest := func(remoteAddr string, values ...string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		for _, value := range values {
			req.Header.Add("X-Forwarded-For", value)
		}
		return req
	}
	tests := []struct {
		name               string
		trustedIPs         []string
		trustedProxyIPs    []string
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
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				return req
			}(),
			expectTrusted: false,
		},
		// Check Unix socket with no trusted IPs configured does not error.
		{
			name:               "UnixSocketWithoutTrustedIPs",
			trustedIPs:         nil,
			reverseProxy:       false,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "@"
				return req
			}(),
			expectTrusted: false,
		},
		// Check Unix socket with trusted IPs configured returns false (no IP to match).
		{
			name:               "UnixSocketWithTrustedIPs",
			trustedIPs:         []string{"127.0.0.1"},
			reverseProxy:       false,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "@"
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
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
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
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "127.0.0.1:44324"
				return req
			}(),
			expectTrusted: false,
		},
		// Check successful trusting of localhost in IPv4.
		{
			name:               "TrustsLocalhostInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Add("X-Forwarded-For", "127.0.0.1")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: true,
		},
		// Check successful trusting of localhost in IPv6.
		{
			name:               "TrustsIP6LocalostInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Add("X-Forwarded-For", "::1")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: true,
		},
		// Check does not trust random IPv4 address.
		{
			name:               "DoesNotTrustRandomIP4Address",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Add("X-Forwarded-For", "12.34.56.78")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: false,
		},
		// Check does not trust random IPv6 address.
		{
			name:               "DoesNotTrustRandomIP6Address",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Add("X-Forwarded-For", "::2")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: false,
		},
		// Check respects correct header.
		{
			name:               "RespectsCorrectHeaderInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Add("X-Real-IP", "::1")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: false,
		},
		// Check doesn't trust if garbage is provided.
		{
			name:               "DoesNotTrustGarbageInReverseProxyMode",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Add("X-Forwarded-For", "adsfljk29242as!!")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: false,
		},
		{
			name:               "IgnoresRealClientHeaderFromUntrustedPeer",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Real-IP", "10.0.0.5")
				req.RemoteAddr = "198.51.100.23:1234"
				return req
			}(),
			expectTrusted: false,
		},
		{
			name:               "UsesTransportAddressForUntrustedPeer",
			trustedIPs:         []string{"198.51.100.23"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Real-IP", "10.0.0.5")
				req.RemoteAddr = "198.51.100.23:1234"
				return req
			}(),
			expectTrusted: true,
		},
		{
			name:               "UsesRealClientHeaderFromTrustedPeer",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Real-IP", "10.0.0.5")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: true,
		},
		{
			name:               "RejectsSpoofedLeftmostXFFEntry",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.10"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Forwarded-For", "10.0.0.5, 198.51.100.23")
				req.RemoteAddr = "192.0.2.10:1234"
				return req
			}(),
			expectTrusted: false,
		},
		{
			name:               "IgnoresXFFFromUntrustedPeer",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("198.51.100.23:1234", "10.0.0.5"),
		},
		{
			name:               "RejectsSpoofedRepeatedXFF",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234", "10.0.0.5", "198.51.100.23, 192.0.2.20"),
		},
		{
			name:               "TrustsClientThroughMultipleProxies",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234", " 10.0.0.5:1234 , 192.0.2.20", "192.0.2.21:443"),
			expectTrusted:      true,
		},
		{
			name:               "TrustsIPv6ClientThroughIPv6Proxy",
			trustedIPs:         []string{"2001:db8:2::/48"},
			trustedProxyIPs:    []string{"2001:db8:1::/48"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("[2001:db8:1::10]:1234", "[2001:db8:2::23]:1234, 2001:db8:1::20"),
			expectTrusted:      true,
		},
		{
			name:               "MalformedRelevantHopIsNotExempt",
			trustedIPs:         []string{"10.0.0.0/8", "192.0.2.0/24"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234", "10.0.0.5, invalid, 192.0.2.20"),
		},
		{
			name:               "MissingXFFDoesNotFallBackToExemptPeer",
			trustedIPs:         []string{"192.0.2.0/24"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234"),
		},
		{
			name:               "EntireChainTrustedUsesLeftmost",
			trustedIPs:         []string{"192.0.2.30"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234", "192.0.2.30, 192.0.2.20"),
			expectTrusted:      true,
		},
		{
			name:               "TrustAllDefaultRetainsLeftmostCompatibility",
			trustedIPs:         []string{"10.0.0.0/8"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234", "10.0.0.5, 198.51.100.23"),
			expectTrusted:      true,
		},
		{
			name:               "ReverseProxyOffIgnoresXFF",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("192.0.2.10:1234", "10.0.0.5"),
		},
		{
			name:               "UnixSocketUsesTrustedProxyChain",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("@", "10.0.0.5, 192.0.2.20"),
			expectTrusted:      true,
		},
		{
			name:               "UnixSocketRejectsSpoofedChain",
			trustedIPs:         []string{"10.0.0.0/8"},
			trustedProxyIPs:    []string{"192.0.2.0/24"},
			reverseProxy:       true,
			realClientIPHeader: "X-Forwarded-For",
			req:                xffRequest("@", "10.0.0.5, 198.51.100.23"),
		},
		// Check doesn't trust if garbage is provided (no reverse-proxy).
		{
			name:               "DoesNotTrustGarbage",
			trustedIPs:         []string{"127.0.0.0/8", "::1"},
			reverseProxy:       false,
			realClientIPHeader: "X-Real-IP",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "adsfljk29242as!!"
				return req
			}(),
			expectTrusted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseTestOptions()
			opts.UpstreamServers = options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:     "static",
						Path:   "/",
						Static: ptr.To(true),
					},
				},
			}
			opts.TrustedIPs = tt.trustedIPs
			opts.TrustedProxyIPs = tt.trustedProxyIPs
			opts.ReverseProxy = tt.reverseProxy
			opts.RealClientIPHeader = tt.realClientIPHeader
			err := validation.Validate(opts)
			require.NoError(t, err)

			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			require.NoError(t, err)

			for _, endpoint := range []struct {
				name          string
				path          string
				trustedStatus int
				deniedStatus  int
			}{
				{"Proxy", "/", http.StatusOK, http.StatusForbidden},
				{"AuthOnly", "/oauth2/auth", http.StatusAccepted, http.StatusUnauthorized},
			} {
				t.Run(endpoint.name, func(t *testing.T) {
					req := tt.req.Clone(tt.req.Context())
					req.URL.Path = endpoint.path
					rw := httptest.NewRecorder()
					proxy.ServeHTTP(rw, req)
					if tt.expectTrusted {
						assert.Equal(t, endpoint.trustedStatus, rw.Code)
					} else {
						assert.Equal(t, endpoint.deniedStatus, rw.Code)
					}
				})
			}
		})
	}
}

func TestTrustedIPsMissingRequestConfiguration(t *testing.T) {
	trustedIPs, err := ip.ParseNetSet([]string{"10.0.0.0/8", "192.0.2.0/24"})
	require.NoError(t, err)
	trustedProxies, err := ip.ParseNetSet([]string{"192.0.2.0/24"})
	require.NoError(t, err)
	parser, err := ip.GetRealClientIPParser("X-Forwarded-For")
	require.NoError(t, err)

	tests := []struct {
		name          string
		scope         *middlewareapi.RequestScope
		remoteAddr    string
		nilParser     bool
		expectTrusted bool
	}{
		{"Missing scope ignores header", nil, "198.51.100.23:1234", false, false},
		{"Missing scope permits direct trusted client", nil, "10.0.0.5:1234", false, true},
		{"Missing trusted proxies ignores header", &middlewareapi.RequestScope{ReverseProxy: true}, "198.51.100.23:1234", false, false},
		{"Missing parser does not fall back to exempt peer", &middlewareapi.RequestScope{ReverseProxy: true, TrustedProxies: trustedProxies}, "192.0.2.10:1234", true, false},
		{"Missing parser permits direct trusted client", &middlewareapi.RequestScope{ReverseProxy: true, TrustedProxies: trustedProxies}, "10.0.0.5:1234", true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy := &OAuthProxy{trustedIPs: trustedIPs, realClientIPParser: parser}
			if test.nilParser {
				proxy.realClientIPParser = nil
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = test.remoteAddr
			req.Header.Set("X-Forwarded-For", "10.0.0.5")
			if test.scope != nil {
				req = middlewareapi.AddRequestScope(req, test.scope)
			}
			assert.Equal(t, test.expectTrusted, proxy.isTrustedIP(req))
		})
	}
}

func Test_buildRoutesAllowlist(t *testing.T) {
	type expectedAllowedRoute struct {
		method      string
		negate      bool
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
					negate:      false,
					regexString: "^/foo/bar",
				},
				{
					method:      "",
					negate:      false,
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
				"!=^/api",
				"METHOD!=^/api",
			},
			expectedRoutes: []expectedAllowedRoute{
				{
					method:      http.MethodGet,
					negate:      false,
					regexString: "^/foo/bar",
				},
				{
					method:      http.MethodPost,
					negate:      false,
					regexString: "^/baz/[0-9]+/thing",
				},
				{
					method:      "",
					negate:      false,
					regexString: "^/all/methods$",
				},
				{
					method:      "WEIRD",
					negate:      false,
					regexString: "^/methods/are/allowed",
				},
				{
					method:      "PATCH",
					negate:      false,
					regexString: "/second/equals?are=handled&just=fine",
				},
				{
					method:      "",
					negate:      true,
					regexString: "^/api",
				},
				{
					method:      "METHOD",
					negate:      true,
					regexString: "^/api",
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
					method:      http.MethodGet,
					regexString: "^/foo/bar",
				},
				{
					method:      http.MethodPost,
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
				assert.Equal(t, route.negate, tc.expectedRoutes[i].negate)
				assert.Equal(t, route.pathRegex.String(), tc.expectedRoutes[i].regexString)
			}
		})
	}
}

func TestApiRoutes(t *testing.T) {

	ajaxAPIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("AJAX API Request"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(ajaxAPIServer.Close)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("API Request"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(apiServer.Close)

	uiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("API Request"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(uiServer.Close)

	opts := baseTestOptions()
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   apiServer.URL,
				Path: "/api",
				URI:  apiServer.URL,
			},
			{
				ID:   ajaxAPIServer.URL,
				Path: "/ajaxapi",
				URI:  ajaxAPIServer.URL,
			},
			{
				ID:   uiServer.URL,
				Path: "/ui",
				URI:  uiServer.URL,
			},
		},
	}
	opts.APIRoutes = []string{
		"^/api",
	}
	opts.SkipProviderButton = true
	err := validation.Validate(opts)
	assert.NoError(t, err)
	proxy, err := NewOAuthProxy(opts, func(_ string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name           string
		contentType    string
		url            string
		shouldRedirect bool
	}{
		{
			name:           "AJAX request matching API regex",
			contentType:    "application/json",
			url:            "/api/v1/UserInfo",
			shouldRedirect: false,
		},
		{
			name:           "AJAX request not matching API regex",
			contentType:    "application/json",
			url:            "/ajaxapi/v1/UserInfo",
			shouldRedirect: false,
		},
		{
			name:           "Other Request matching API regex",
			contentType:    "application/grpcwebtext",
			url:            "/api/v1/UserInfo",
			shouldRedirect: false,
		},
		{
			name:           "UI request",
			contentType:    "html",
			url:            "/ui/index.html",
			shouldRedirect: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			req.Header.Set("Accept", tc.contentType)
			assert.NoError(t, err)

			rw := httptest.NewRecorder()
			proxy.ServeHTTP(rw, req)

			if tc.shouldRedirect {
				assert.Equal(t, 302, rw.Code)
			} else {
				assert.Equal(t, 401, rw.Code)
			}
		})
	}
}

func TestSkipAuthPathRouting(t *testing.T) {
	for _, mode := range []string{"default proxy", "raw proxy", "external auth"} {
		t.Run(mode, func(t *testing.T) {
			var hits, mutations atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				// Model the reported servlet ordering: strip literal matrix parameters,
				// then decode and resolve dot segments.
				segments := strings.Split(r.URL.EscapedPath(), "/")
				for i, segment := range segments {
					segments[i], _, _ = strings.Cut(segment, ";")
				}
				decodedPath, err := url.PathUnescape(strings.Join(segments, "/"))
				if err != nil {
					http.Error(w, "invalid fixture path", http.StatusBadRequest)
					return
				}
				routedPath := path.Clean(decodedPath)
				if strings.HasPrefix(routedPath, "/protected/") && r.Method == http.MethodPost {
					mutations.Add(1)
				}
				_, _ = io.WriteString(w, r.RequestURI)
			}))
			t.Cleanup(backend.Close)

			opts := baseTestOptions()
			opts.ForceJSONErrors = true
			if mode == "external auth" {
				opts.ReverseProxy = true
				opts.TrustedProxyIPs = []string{"127.0.0.1/32"}
			}
			opts.SkipAuthRoutes = []string{"POST=^/public/"}
			opts.UpstreamServers = options.UpstreamConfig{
				ProxyRawPath: ptr.To(mode == "raw proxy"),
				Upstreams: []options.Upstream{{
					ID: "backend", Path: "/", URI: backend.URL,
				}},
			}
			require.NoError(t, validation.Validate(opts))
			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			require.NoError(t, err)

			newFrontend := func(t *testing.T, proxy *OAuthProxy) *httptest.Server {
				t.Helper()
				var handler http.Handler = proxy
				if mode == "external auth" {
					backendURL, err := url.Parse(backend.URL)
					require.NoError(t, err)
					forward := httputil.NewSingleHostReverseProxy(backendURL)
					handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						authReq := httptest.NewRequest(r.Method, "/oauth2/auth", nil)
						authReq.RemoteAddr = "127.0.0.1:4180"
						authReq.Header = r.Header.Clone()
						authReq.Header.Set("X-Forwarded-Uri", r.RequestURI)
						authResponse := httptest.NewRecorder()
						proxy.ServeHTTP(authResponse, authReq)
						if authResponse.Code != http.StatusAccepted {
							w.WriteHeader(authResponse.Code)
							return
						}
						forward.ServeHTTP(w, r)
					})
				}
				return httptest.NewServer(handler)
			}
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}

			send := func(t *testing.T, server, target string, cookies []*http.Cookie) (int, string) {
				t.Helper()
				req, err := http.NewRequest(http.MethodPost, server+target, nil)
				require.NoError(t, err)
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				return resp.StatusCode, string(body)
			}

			created, expires := time.Now(), time.Now().Add(time.Hour)
			cookieResponse := httptest.NewRecorder()
			require.NoError(t, proxy.SaveSession(cookieResponse, httptest.NewRequest(http.MethodGet, "/", nil), &sessions.SessionState{
				User: "user", Email: "user@example.com", CreatedAt: &created, ExpiresOn: &expires,
			}))
			for _, tc := range []struct {
				name            string
				target          string
				pattern         string
				public          bool
				protected       bool
				routerRedirect  bool
				decodedRedirect bool
			}{
				{name: "encoded parent", target: "/public/%2e%2e/protected/change", protected: true, decodedRedirect: true},
				{name: "mixed encoded parent", target: "/public/.%2E/protected/change", protected: true, decodedRedirect: true},
				{name: "encoded separators", target: "/public%2f..%2fprotected/change", protected: true, decodedRedirect: true},
				{name: "literal parent", target: "/public/../protected/change", protected: true, routerRedirect: true},
				{name: "current segment", target: "/public/./file", routerRedirect: true},
				{name: "matrix parent", target: "/public/..;/protected/change", protected: true},
				{name: "encoded matrix parent", target: "/public/%2e%2e;/protected/change", protected: true},
				{name: "encoded matrix semicolon control", target: "/public/%2e%2e%3b/protected/change"},
				{name: "matrix value", target: "/public/..;version=1/protected/change", protected: true},
				{name: "matrix current and parent", target: "/public/.;/..;/protected/change", protected: true},
				{name: "nested matrix parents", target: "/public/a/..;/..;/protected/change", protected: true},
				{name: "leading double slash", target: "//protected/public", pattern: "^/public$", protected: true, routerRedirect: true},
				{name: "encoded leading slash", target: "/%2fprotected/public", pattern: "^/public$", protected: true, decodedRedirect: true},
				{name: "repeated slash", target: "/public//file", routerRedirect: true},
				{name: "encoded repeated slash", target: "/public/%2ffile", decodedRedirect: true},
				{name: "valid semicolon", target: "/public/file;version=1"},
				{name: "encoded semicolon", target: "/public/file%3bversion=1"},
				{name: "fragment suffix", target: "/public/file%23suffix"},
				{name: "ordinary public", target: "/public/file", public: true},
				{name: "public query", target: "/public/file?next=/../protected;v=1&tag=%23", public: true},
				{name: "public trailing slash", target: "/public/", pattern: "^/public/$", public: true},
				{name: "trailing slash is significant", target: "/public/file/", pattern: "^/public/file$"},
				{name: "escaped space", target: "/public/a%20b", pattern: "^/public/a b$", public: true},
				{name: "escaped letter", target: "/public/%66ile", pattern: "^/public/file$", public: true},
				{name: "ordinary protected", target: "/protected/change", protected: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// Prove each original target reaches the intended downstream fixture.
					status, body := send(t, backend.URL, tc.target, nil)
					require.Equal(t, http.StatusOK, status)
					require.Equal(t, tc.target, body)
					require.EqualValues(t, 1, hits.Swap(0))
					var wantMutations int32
					if tc.protected {
						wantMutations = 1
					}
					require.Equal(t, wantMutations, mutations.Swap(0))

					pattern := tc.pattern
					if pattern == "" {
						pattern = "^/public/"
					}
					configs := []string{"regex", "route"}
					if tc.pattern == "" || tc.protected {
						configs = append(configs, "negated route")
					}
					for _, config := range configs {
						t.Run(config, func(t *testing.T) {
							opts.SkipAuthRegex, opts.SkipAuthRoutes = nil, nil
							switch config {
							case "regex":
								opts.SkipAuthRegex = []string{pattern}
							case "negated route":
								opts.SkipAuthRoutes = []string{"POST!=^/protected"}
							default:
								opts.SkipAuthRoutes = []string{"POST=" + pattern}
							}
							testProxy, err := NewOAuthProxy(opts, func(string) bool { return true })
							require.NoError(t, err)
							frontend := newFrontend(t, testProxy)
							t.Cleanup(frontend.Close)

							wantStatus := http.StatusUnauthorized
							if tc.public {
								wantStatus = http.StatusOK
							} else if tc.routerRedirect && mode != "external auth" {
								wantStatus = http.StatusMovedPermanently
							}
							status, _ := send(t, frontend.URL, tc.target, nil)
							assert.Equal(t, wantStatus, status)
							var wantHits int32
							if tc.public {
								wantHits = 1
							}
							assert.Equal(t, wantHits, hits.Swap(0))
							assert.Zero(t, mutations.Swap(0))

							wantStatus = http.StatusOK
							wantHits = 1
							redirects := (tc.routerRedirect && mode != "external auth") ||
								(tc.decodedRedirect && mode == "default proxy")
							if redirects {
								wantStatus = http.StatusMovedPermanently
								wantHits = 0
							}
							status, body := send(t, frontend.URL, tc.target, cookieResponse.Result().Cookies())
							assert.Equal(t, wantStatus, status)
							if !redirects {
								assert.Equal(t, tc.target, body)
							}
							assert.Equal(t, wantHits, hits.Swap(0))
							assert.Equal(t, wantMutations*wantHits, mutations.Swap(0))
						})
					}
				})
			}
		})
	}
}

func TestSkipAuthForwardedTargets(t *testing.T) {
	for _, config := range []string{"regex", "route", "negated route", "empty path"} {
		t.Run(config, func(t *testing.T) {
			opts := baseTestOptions()
			opts.ReverseProxy = true
			opts.TrustedProxyIPs = []string{"127.0.0.1/32"}
			switch config {
			case "regex":
				opts.SkipAuthRegex = []string{".*"}
			case "route":
				opts.SkipAuthRoutes = []string{"GET=.*"}
			case "negated route":
				opts.SkipAuthRoutes = []string{"GET!=^/protected"}
			case "empty path":
				opts.SkipAuthRoutes = []string{"GET=^$"}
			}
			require.NoError(t, validation.Validate(opts))
			proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
			require.NoError(t, err)
			created, expires := time.Now(), time.Now().Add(time.Hour)
			cookieResponse := httptest.NewRecorder()
			require.NoError(t, proxy.SaveSession(cookieResponse, httptest.NewRequest(http.MethodGet, "/", nil), &sessions.SessionState{
				User: "user", Email: "user@example.com", CreatedAt: &created, ExpiresOn: &expires,
			}))

			for _, target := range []string{
				"/public/../protected", "/public/%2e%2e/protected",
				"//protected/public", "/public//file",
				"/public/..;/protected", "/public/%2e%2e%3b/protected",
				"/public/file;version=1", "/public/%zz", "/public/%",
				"public/file", "https://example.com/public", "example.com:443", "*",
				"/public#fragment", "/public%23fragment", "/public%3fquery",
				"/public\\file", "/public/%00",
			} {
				t.Run(target, func(t *testing.T) {
					for _, authenticated := range []bool{false, true} {
						req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
						req.RemoteAddr = "127.0.0.1:4180"
						req.Header.Set("X-Forwarded-Uri", target)
						if authenticated {
							for _, cookie := range cookieResponse.Result().Cookies() {
								req.AddCookie(cookie)
							}
						}
						rw := httptest.NewRecorder()
						proxy.ServeHTTP(rw, req)
						wantStatus := http.StatusUnauthorized
						if authenticated {
							wantStatus = http.StatusAccepted
						}
						assert.Equal(t, wantStatus, rw.Code)
						assert.Equal(t, target, req.Header.Get("X-Forwarded-Uri"))
						assert.Equal(t, "/oauth2/auth", req.RequestURI)
					}
				})
			}

			for _, method := range []string{http.MethodGet, http.MethodPost} {
				t.Run("ordinary public "+method, func(t *testing.T) {
					req := httptest.NewRequest(method, "/oauth2/auth", nil)
					req.RemoteAddr = "127.0.0.1:4180"
					req.Header.Set("X-Forwarded-Uri", "/public/file?query=value")
					rw := httptest.NewRecorder()
					proxy.ServeHTTP(rw, req)
					wantStatus := http.StatusUnauthorized
					if config != "empty path" && (config == "regex" || method == http.MethodGet) {
						wantStatus = http.StatusAccepted
					}
					assert.Equal(t, wantStatus, rw.Code)
				})
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
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
		},
	}
	opts.SkipAuthRegex = []string{
		"^/skip/auth/regex$",
		"^/public/.*/endpoint$",
	}
	opts.SkipAuthRoutes = []string{
		"GET=^/skip/auth/routes/get",
		"^/foo/.*/bar$",
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
			method:  http.MethodGet,
			url:     "/skip/auth/regex",
			allowed: true,
		},
		{
			name:    "Regex POST allowed ",
			method:  http.MethodPost,
			url:     "/skip/auth/regex",
			allowed: true,
		},
		{
			name:    "Regex denied",
			method:  http.MethodGet,
			url:     "/wrong/denied",
			allowed: false,
		},
		{
			name:    "Regex allowed with fragment-free path",
			method:  http.MethodGet,
			url:     "/public/legit/endpoint",
			allowed: true,
		},
		{
			name:    "Regex denied when path contains encoded fragment suffix",
			method:  http.MethodGet,
			url:     "/public/secret%23/endpoint",
			allowed: false,
		},
		{
			name:    "Route allowed",
			method:  http.MethodGet,
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
			method:  http.MethodGet,
			url:     "/skip/auth/routes/wrong/path",
			allowed: false,
		},
		{
			name:    "Route denied with wrong path and method",
			method:  http.MethodPost,
			url:     "/skip/auth/routes/wrong/path",
			allowed: false,
		},
		{
			name:    "Route allowed with fragment-free path",
			method:  http.MethodGet,
			url:     "/foo/public/bar",
			allowed: true,
		},
		{
			name:    "Route denied when path contains encoded fragment suffix",
			method:  http.MethodGet,
			url:     "/foo/secret%23/bar",
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

func TestAllowedRequestWithForwardedUriHeader(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.ReverseProxy = true
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
		},
	}
	opts.SkipAuthRegex = []string{
		"^/skip/auth/regex$",
		"^/public/.*/endpoint$",
	}
	opts.SkipAuthRoutes = []string{
		"GET=^/skip/auth/routes/get",
		"^/foo/.*/bar$",
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
			method:  http.MethodGet,
			url:     "/skip/auth/regex",
			allowed: true,
		},
		{
			name:    "Regex POST allowed ",
			method:  http.MethodPost,
			url:     "/skip/auth/regex",
			allowed: true,
		},
		{
			name:    "Regex denied",
			method:  http.MethodGet,
			url:     "/wrong/denied",
			allowed: false,
		},
		{
			name:    "Regex allowed with fragment-free path",
			method:  http.MethodGet,
			url:     "/public/legit/endpoint",
			allowed: true,
		},
		{
			name:    "Regex denied when X-Forwarded-Uri contains an encoded fragment suffix",
			method:  http.MethodGet,
			url:     "/public/secret%23/endpoint",
			allowed: false,
		},
		{
			name:    "Route allowed",
			method:  http.MethodGet,
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
			method:  http.MethodGet,
			url:     "/skip/auth/routes/wrong/path",
			allowed: false,
		},
		{
			name:    "Route denied with wrong path and method",
			method:  http.MethodPost,
			url:     "/skip/auth/routes/wrong/path",
			allowed: false,
		},
		{
			name:    "Route allowed with fragment-free path",
			method:  http.MethodGet,
			url:     "/foo/public/bar",
			allowed: true,
		},
		{
			name:    "Route denied when X-Forwarded-Uri contains an encoded fragment suffix",
			method:  http.MethodGet,
			url:     "/foo/secret%23/bar",
			allowed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, opts.ProxyPrefix+authOnlyPath, nil)
			req.Header.Set("X-Forwarded-Uri", tc.url)
			req.RemoteAddr = "127.0.0.1:4180"
			assert.NoError(t, err)

			rw := httptest.NewRecorder()
			proxy.ServeHTTP(rw, req)

			if tc.allowed {
				assert.Equal(t, 202, rw.Code)
			} else {
				assert.Equal(t, 401, rw.Code)
			}
		})
	}
}

func TestAllowedRequestWithForwardedUriHeaderRequiresTrustedProxy(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.ReverseProxy = true
	opts.TrustedProxyIPs = []string{"127.0.0.1/32"}
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
		},
	}
	opts.SkipAuthRegex = []string{"^/skip/auth/regex$"}

	err := validation.Validate(opts)
	assert.NoError(t, err)

	proxy, err := NewOAuthProxy(opts, func(_ string) bool { return true })
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, opts.ProxyPrefix+authOnlyPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = "192.0.2.10:4180"
	req.Header.Set("X-Forwarded-Uri", "/skip/auth/regex")

	rw := httptest.NewRecorder()
	proxy.ServeHTTP(rw, req)

	assert.Equal(t, 401, rw.Code)
}

func TestAllowedRequestNegateWithoutMethod(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("Allowed Request"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
		},
	}
	opts.SkipAuthRoutes = []string{
		"!=^/api", // any non-api routes
		"POST=^/api/public-entity/?$",
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
			name:    "Some static file allowed",
			method:  http.MethodGet,
			url:     "/static/file.txt",
			allowed: true,
		},
		{
			name:    "POST to contact form allowed",
			method:  http.MethodPost,
			url:     "/contact",
			allowed: true,
		},
		{
			name:    "Regex POST allowed",
			method:  http.MethodPost,
			url:     "/api/public-entity",
			allowed: true,
		},
		{
			name:    "Regex POST with trailing slash allowed",
			method:  http.MethodPost,
			url:     "/api/public-entity/",
			allowed: true,
		},
		{
			name:    "Regex GET api route denied",
			method:  http.MethodGet,
			url:     "/api/users",
			allowed: false,
		},
		{
			name:    "Regex POST api route denied",
			method:  http.MethodPost,
			url:     "/api/users",
			allowed: false,
		},
		{
			name:    "Regex DELETE api route denied",
			method:  "DELETE",
			url:     "/api/users/1",
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

func TestAllowedRequestNegateWithMethod(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, err := w.Write([]byte("Allowed Request"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(upstreamServer.Close)

	opts := baseTestOptions()
	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   upstreamServer.URL,
				Path: "/",
				URI:  upstreamServer.URL,
			},
		},
	}
	opts.SkipAuthRoutes = []string{
		"GET!=^/api", // any non-api routes
		"POST=^/api/public-entity/?$",
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
			name:    "Some static file allowed",
			method:  http.MethodGet,
			url:     "/static/file.txt",
			allowed: true,
		},
		{
			name:    "POST to contact form not allowed",
			method:  http.MethodPost,
			url:     "/contact",
			allowed: false,
		},
		{
			name:    "Regex POST allowed",
			method:  http.MethodPost,
			url:     "/api/public-entity",
			allowed: true,
		},
		{
			name:    "Regex POST with trailing slash allowed",
			method:  http.MethodPost,
			url:     "/api/public-entity/",
			allowed: true,
		},
		{
			name:    "Regex GET api route denied",
			method:  http.MethodGet,
			url:     "/api/users",
			allowed: false,
		},
		{
			name:    "Regex POST api route denied",
			method:  http.MethodPost,
			url:     "/api/users",
			allowed: false,
		},
		{
			name:    "Regex DELETE api route denied",
			method:  "DELETE",
			url:     "/api/users/1",
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
		querystring        string
		expectUnauthorized bool
	}{
		{
			name:               "NoAllowedGroups",
			allowedGroups:      []string{},
			groups:             []string{},
			querystring:        "",
			expectUnauthorized: false},
		{
			name:               "NoAllowedGroupsUserHasGroups",
			allowedGroups:      []string{},
			groups:             []string{"a", "b"},
			querystring:        "",
			expectUnauthorized: false},
		{
			name:               "UserInAllowedGroup",
			allowedGroups:      []string{"a"},
			groups:             []string{"a", "b"},
			querystring:        "",
			expectUnauthorized: false},
		{
			name:               "UserNotInAllowedGroup",
			allowedGroups:      []string{"a"},
			groups:             []string{"c"},
			querystring:        "",
			expectUnauthorized: true},
		{
			name:               "UserInQuerystringGroup",
			allowedGroups:      []string{"a", "b"},
			groups:             []string{"a", "c"},
			querystring:        "?allowed_groups=a",
			expectUnauthorized: false},
		{
			name:               "UserInMultiParamQuerystringGroup",
			allowedGroups:      []string{"a", "b"},
			groups:             []string{"b"},
			querystring:        "?allowed_groups=a&allowed_groups=b,d",
			expectUnauthorized: false},
		{
			name:               "UserInOnlyQuerystringGroup",
			allowedGroups:      []string{},
			groups:             []string{"a", "c"},
			querystring:        "?allowed_groups=a,b",
			expectUnauthorized: false},
		{
			name:               "UserInDelimitedQuerystringGroup",
			allowedGroups:      []string{"a", "b", "c"},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=a,c",
			expectUnauthorized: false},
		{
			name:               "UserNotInQuerystringGroup",
			allowedGroups:      []string{},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=a,b",
			expectUnauthorized: true},
		{
			name:               "UserInConfigGroupNotInQuerystringGroup",
			allowedGroups:      []string{"a", "b", "c"},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=a,b",
			expectUnauthorized: true},
		{
			name:               "UserInQuerystringGroupNotInConfigGroup",
			allowedGroups:      []string{"a", "b"},
			groups:             []string{"c"},
			querystring:        "?allowed_groups=b,c",
			expectUnauthorized: true},
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
				opts.Providers[0].AllowedGroups = tt.allowedGroups
				opts.UpstreamServers = options.UpstreamConfig{
					Upstreams: []options.Upstream{
						{
							ID:   upstreamServer.URL,
							Path: "/",
							URI:  upstreamServer.URL,
						},
					},
				}
			})
			if err != nil {
				t.Fatal(err)
			}

			test.req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("/%s", tt.querystring), nil)

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
				opts.Providers[0].AllowedGroups = tc.allowedGroups
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

func TestAuthOnlyAllowedGroupsWithSkipMethods(t *testing.T) {
	testCases := []struct {
		name               string
		groups             []string
		method             string
		ip                 string
		withSession        bool
		expectedStatusCode int
	}{
		{
			name:               "UserWithGroupSkipAuthPreflight",
			groups:             []string{"a", "c"},
			method:             http.MethodOptions,
			ip:                 "1.2.3.5:43670",
			withSession:        true,
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserWithGroupTrustedIp",
			groups:             []string{"a", "c"},
			method:             http.MethodGet,
			ip:                 "1.2.3.4:43670",
			withSession:        true,
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserWithoutGroupSkipAuthPreflight",
			groups:             []string{"c"},
			method:             http.MethodOptions,
			ip:                 "1.2.3.5:43670",
			withSession:        true,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserWithoutGroupTrustedIp",
			groups:             []string{"c"},
			method:             http.MethodGet,
			ip:                 "1.2.3.4:43670",
			withSession:        true,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserWithoutSessionSkipAuthPreflight",
			method:             http.MethodOptions,
			ip:                 "1.2.3.5:43670",
			withSession:        false,
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserWithoutSessionTrustedIp",
			method:             http.MethodGet,
			ip:                 "1.2.3.4:43670",
			withSession:        false,
			expectedStatusCode: http.StatusAccepted,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test, err := NewAuthOnlyEndpointTest("?allowed_groups=a,b", func(opts *options.Options) {
				opts.SkipAuthPreflight = true
				opts.TrustedIPs = []string{"1.2.3.4"}
			})
			if err != nil {
				t.Fatal(err)
			}

			test.req.Method = tc.method
			test.req.RemoteAddr = tc.ip

			if tc.withSession {
				created := time.Now()
				session := &sessions.SessionState{
					Groups:      tc.groups,
					Email:       "test",
					AccessToken: "oauth_token",
					CreatedAt:   &created,
				}
				err = test.SaveSession(session)
			}
			assert.NoError(t, err)

			test.proxy.ServeHTTP(test.rw, test.req)

			assert.Equal(t, tc.expectedStatusCode, test.rw.Code)
		})
	}
}

func TestAuthOnlyAllowedEmailDomains(t *testing.T) {
	testCases := []struct {
		name               string
		email              string
		querystring        string
		expectedStatusCode int
	}{
		{
			name:               "NotEmailRestriction",
			email:              "toto@example.com",
			querystring:        "",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInAllowedEmailDomain",
			email:              "toto@example.com",
			querystring:        "?allowed_email_domains=example.com",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserNotInAllowedEmailDomain",
			email:              "toto@example.com",
			querystring:        "?allowed_email_domains=a.example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserNotInAllowedEmailDomains",
			email:              "toto@example.com",
			querystring:        "?allowed_email_domains=a.example.com,b.example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserInAllowedEmailDomains",
			email:              "toto@example.com",
			querystring:        "?allowed_email_domains=a.example.com,example.com",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInAllowedEmailDomainWildcard",
			email:              "toto@foo.example.com",
			querystring:        "?allowed_email_domains=*.example.com",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserNotInAllowedEmailDomainWildcard",
			email:              "toto@example.com",
			querystring:        "?allowed_email_domains=*.a.example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserInAllowedEmailDomainsWildcard",
			email:              "toto@example.com",
			querystring:        "?allowed_email_domains=*.a.example.com,*.b.example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserInAllowedEmailDomainsWildcard",
			email:              "toto@c.example.com",
			querystring:        "?allowed_email_domains=a.b.c.example.com,*.c.example.com",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserWithMultipleAtSignsExactDomain",
			email:              "attacker@evil.com@example.com",
			querystring:        "?allowed_email_domains=example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserWithMultipleAtSignsWildcardDomain",
			email:              "attacker@evil.com@foo.example.com",
			querystring:        "?allowed_email_domains=*.example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserWithMultipleAtSignsDotPrefixedDomain",
			email:              "attacker@evil.com@foo.example.com",
			querystring:        "?allowed_email_domains=.example.com",
			expectedStatusCode: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			groups := []string{}

			created := time.Now()

			session := &sessions.SessionState{
				Groups:      groups,
				Email:       tc.email,
				AccessToken: "oauth_token",
				CreatedAt:   &created,
			}

			test, err := NewAuthOnlyEndpointTest(tc.querystring, func(opts *options.Options) {})
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

func TestStateEncodesCorrectly(t *testing.T) {
	state := "some_state_to_test"
	nonce := "some_nonce_to_test"

	encodedResult := encodeState(nonce, state, true)
	assert.Equal(t, "c29tZV9ub25jZV90b190ZXN0OnNvbWVfc3RhdGVfdG9fdGVzdA", encodedResult)

	notEncodedResult := encodeState(nonce, state, false)
	assert.Equal(t, "some_nonce_to_test:some_state_to_test", notEncodedResult)
}

func TestStateDecodesCorrectly(t *testing.T) {
	nonce, redirect, _ := decodeState("c29tZV9ub25jZV90b190ZXN0OnNvbWVfc3RhdGVfdG9fdGVzdA", true)

	assert.Equal(t, "some_nonce_to_test", nonce)
	assert.Equal(t, "some_state_to_test", redirect)

	nonce2, redirect2, _ := decodeState("some_nonce_to_test:some_state_to_test", false)

	assert.Equal(t, "some_nonce_to_test", nonce2)
	assert.Equal(t, "some_state_to_test", redirect2)
}

func TestAuthOnlyAllowedEmails(t *testing.T) {
	testCases := []struct {
		name               string
		email              string
		querystring        string
		expectedStatusCode int
	}{
		{
			name:               "NotEmailRestriction",
			email:              "toto@example.com",
			querystring:        "",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserInAllowedEmail",
			email:              "toto@example.com",
			querystring:        "?allowed_emails=toto@example.com",
			expectedStatusCode: http.StatusAccepted,
		},
		{
			name:               "UserNotInAllowedEmail",
			email:              "toto@example.com",
			querystring:        "?allowed_emails=tete@example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserNotInAllowedEmails",
			email:              "toto@example.com",
			querystring:        "?allowed_emails=tete@example.com,tutu@example.com",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "UserInAllowedEmails",
			email:              "toto@example.com",
			querystring:        "?allowed_emails=tete@example.com,toto@example.com",
			expectedStatusCode: http.StatusAccepted,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			groups := []string{}

			created := time.Now()

			session := &sessions.SessionState{
				Groups:      groups,
				Email:       tc.email,
				AccessToken: "oauth_token",
				CreatedAt:   &created,
			}

			test, err := NewAuthOnlyEndpointTest(tc.querystring, func(opts *options.Options) {})
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

func TestGetOAuthRedirectURI(t *testing.T) {
	tests := []struct {
		name      string
		setupOpts func(*options.Options) *options.Options
		req       *http.Request
		want      string
	}{
		{
			name: "redirect with https schema",
			setupOpts: func(baseOpts *options.Options) *options.Options {
				return baseOpts
			},
			req: &http.Request{
				Host: "example",
				URL: &url.URL{
					Scheme: schemeHTTPS,
				},
			},
			want: "https://example/oauth2/callback",
		},
		{
			name: "redirect with http schema",
			setupOpts: func(baseOpts *options.Options) *options.Options {
				baseOpts.Cookie.Secure = false
				return baseOpts
			},
			req: &http.Request{
				Host: "example",
				URL: &url.URL{
					Scheme: schemeHTTP,
				},
			},
			want: "http://example/oauth2/callback",
		},
		{
			name: "relative redirect url",
			setupOpts: func(baseOpts *options.Options) *options.Options {
				baseOpts.RelativeRedirectURL = true
				return baseOpts
			},
			req:  &http.Request{},
			want: "/oauth2/callback",
		},
		{
			name: "proxy prefix",
			setupOpts: func(baseOpts *options.Options) *options.Options {
				baseOpts.ProxyPrefix = "/prefix"
				return baseOpts
			},
			req: &http.Request{
				Host: "example",
				URL: &url.URL{
					Scheme: schemeHTTP,
				},
			},
			want: "https://example/prefix/callback",
		},
		{
			name: "proxy prefix with relative redirect",
			setupOpts: func(baseOpts *options.Options) *options.Options {
				baseOpts.ProxyPrefix = "/prefix"
				baseOpts.RelativeRedirectURL = true
				return baseOpts
			},
			req: &http.Request{
				Host: "example",
				URL: &url.URL{
					Scheme: schemeHTTP,
				},
			},
			want: "/prefix/callback",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseOpts := baseTestOptions()
			err := validation.Validate(baseOpts)
			assert.NoError(t, err)

			proxy, err := NewOAuthProxy(tt.setupOpts(baseOpts), func(string) bool { return true })
			assert.NoError(t, err)

			assert.Equalf(t, tt.want, proxy.getOAuthRedirectURI(tt.req), "getOAuthRedirectURI(%v)", tt.req)
		})
	}
}

func TestIdTokenPlaceholderInSignOut(t *testing.T) {
	opts := baseTestOptions()
	opts.WhitelistDomains = []string{"my-oidc-provider.example.com"}

	err := validation.Validate(opts)
	assert.NoError(t, err)

	const emailAddress = "john.doe@example.com"
	const userName = "9fcab5c9b889a557"
	created := time.Now()

	session := &sessions.SessionState{
		User:        userName,
		Groups:      []string{"a", "b"},
		Email:       emailAddress,
		IDToken:     "eYjjjjjj.vvvv.ddd",
		AccessToken: "oauth_token",
		CreatedAt:   &created,
	}

	proxy, err := NewOAuthProxy(opts, func(email string) bool {
		return true
	})
	assert.NoError(t, err)

	// Save the required session
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	err = proxy.sessionStore.Save(rw, req, session)
	assert.NoError(t, err)

	rw = httptest.NewRecorder()

	rdUrl := url.QueryEscape("https://my-oidc-provider.example.com/sign_out_page?id_token_hint={id_token}&post_logout_redirect_uri=https://my-app.example.com/")
	req, _ = http.NewRequest(http.MethodGet, "/oauth2/sign_out?rd="+rdUrl, nil)
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
		RequestID: "11111111-2222-4333-8444-555555555555",
		Session:   session,
	})

	proxy.SignOut(rw, req)
	newLocation := rw.Header().Values("Location")[0]

	assert.Equal(t, "https://my-oidc-provider.example.com/sign_out_page?id_token_hint=eYjjjjjj.vvvv.ddd&post_logout_redirect_uri=https://my-app.example.com/", newLocation)
}
