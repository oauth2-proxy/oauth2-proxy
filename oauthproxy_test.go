package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/mbland/hmacauth"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/sessions/cookie"
	"github.com/pusher/oauth2_proxy/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

func init() {
	logger.SetFlags(logger.Lshortfile)

}

type WebSocketOrRestHandler struct {
	restHandler http.Handler
	wsHandler   http.Handler
}

func (h *WebSocketOrRestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") == "websocket" {
		h.wsHandler.ServeHTTP(w, r)
	} else {
		h.restHandler.ServeHTTP(w, r)
	}
}

func TestWebSocketProxy(t *testing.T) {
	handler := WebSocketOrRestHandler{
		restHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			hostname, _, _ := net.SplitHostPort(r.Host)
			w.Write([]byte(hostname))
		}),
		wsHandler: websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			var data []byte
			err := websocket.Message.Receive(ws, &data)
			if err != nil {
				t.Fatalf("err %s", err)
				return
			}
			err = websocket.Message.Send(ws, data)
			if err != nil {
				t.Fatalf("err %s", err)
			}
			return
		}),
	}
	backend := httptest.NewServer(&handler)
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	options := NewOptions()
	var auth hmacauth.HmacAuth
	options.PassHostHeader = true
	proxyHandler := NewWebSocketOrRestReverseProxy(backendURL, options, auth)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	frontendURL, _ := url.Parse(frontend.URL)
	frontendWSURL := "ws://" + frontendURL.Host + "/"

	ws, err := websocket.Dial(frontendWSURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("err %s", err)
	}
	request := []byte("hello, world!")
	err = websocket.Message.Send(ws, request)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	var response = make([]byte, 1024)
	websocket.Message.Receive(ws, &response)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	if g, e := string(request), string(response); g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	backendHostname, _, _ := net.SplitHostPort(backendURL.Host)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func TestNewReverseProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		hostname, _, _ := net.SplitHostPort(r.Host)
		w.Write([]byte(hostname))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	backendHost := net.JoinHostPort(backendHostname, backendPort)
	proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")

	proxyHandler := NewReverseProxy(proxyURL, &Options{FlushInterval: time.Second})
	setProxyUpstreamHostHeader(proxyHandler, proxyURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func TestEncodedSlashes(t *testing.T) {
	var seen string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		seen = r.RequestURI
	}))
	defer backend.Close()

	b, _ := url.Parse(backend.URL)
	proxyHandler := NewReverseProxy(b, &Options{FlushInterval: time.Second})
	setProxyDirector(proxyHandler)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	f, _ := url.Parse(frontend.URL)
	encodedPath := "/a%2Fb/?c=1"
	getReq := &http.Request{URL: &url.URL{Scheme: "http", Host: f.Host, Opaque: encodedPath}}
	_, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	if seen != encodedPath {
		t.Errorf("got bad request %q expected %q", seen, encodedPath)
	}
}

func TestRobotsTxt(t *testing.T) {
	opts := NewOptions()
	opts.ClientID = "asdlkjx"
	opts.ClientSecret = "alkgks"
	opts.CookieSecret = "asdkugkj"
	opts.Validate()

	proxy := NewOAuthProxy(opts, func(string) bool { return true })
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/robots.txt", nil)
	proxy.ServeHTTP(rw, req)
	assert.Equal(t, 200, rw.Code)
	assert.Equal(t, "User-agent: *\nDisallow: /", rw.Body.String())
}

func TestIsValidRedirect(t *testing.T) {
	opts := NewOptions()
	opts.ClientID = "skdlfj"
	opts.ClientSecret = "fgkdsgj"
	opts.CookieSecret = "ljgiogbj"
	// Should match domains that are exactly foo.bar and any subdomain of bar.foo
	opts.WhitelistDomains = []string{
		"foo.bar",
		".bar.foo",
		"port.bar:8080",
		".sub.port.bar:8080",
		"anyport.bar:*",
		".sub.anyport.bar:*",
	}
	opts.Validate()

	proxy := NewOAuthProxy(opts, func(string) bool { return true })

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

type TestProvider struct {
	*providers.ProviderData
	EmailAddress   string
	ValidToken     bool
	GroupValidator func(string) bool
}

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

func (tp *TestProvider) GetEmailAddress(session *sessions.SessionState) (string, error) {
	return tp.EmailAddress, nil
}

func (tp *TestProvider) ValidateSessionState(session *sessions.SessionState) bool {
	return tp.ValidToken
}

func (tp *TestProvider) ValidateGroup(email string) bool {
	if tp.GroupValidator != nil {
		return tp.GroupValidator(email)
	}
	return true
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
		w.Write([]byte(payload))
	}))
	opts := NewOptions()
	opts.Upstreams = append(opts.Upstreams, providerServer.URL)
	// The CookieSecret must be 32 bytes in order to create the AES
	// cipher.
	opts.CookieSecret = "xyzzyplughxyzzyplughxyzzyplughxp"
	opts.ClientID = "dlgkj"
	opts.ClientSecret = "alkgret"
	opts.CookieSecure = false
	opts.PassBasicAuth = true
	opts.PassUserHeaders = true
	opts.BasicAuthPassword = "This is a secure password"
	opts.Validate()

	providerURL, _ := url.Parse(providerServer.URL)
	const emailAddress = "john.doe@example.com"

	opts.provider = NewTestProvider(providerURL, emailAddress)
	proxy := NewOAuthProxy(opts, func(email string) bool {
		return email == emailAddress
	})

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/oauth2/callback?code=callback_code&state=nonce:",
		strings.NewReader(""))
	req.AddCookie(proxy.MakeCSRFCookie(req, "nonce", proxy.CookieExpire, time.Now()))
	proxy.ServeHTTP(rw, req)
	if rw.Code >= 400 {
		t.Fatalf("expected 3xx got %d", rw.Code)
	}
	cookie := rw.HeaderMap["Set-Cookie"][1]

	cookieName := proxy.CookieName
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

	req, _ = http.NewRequest("GET", "/", strings.NewReader(""))
	req.AddCookie(&http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(time.Duration(24)),
		HttpOnly: true,
	})
	req.AddCookie(proxy.MakeCSRFCookie(req, "nonce", proxy.CookieExpire, time.Now()))

	rw = httptest.NewRecorder()
	proxy.ServeHTTP(rw, req)

	// The username in the basic auth credentials is expected to be equal to the email address from the
	// auth response, so we use the same variable here.
	expectedHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(emailAddress+":"+opts.BasicAuthPassword))
	assert.Equal(t, expectedHeader, rw.Body.String())
	providerServer.Close()
}

type PassAccessTokenTest struct {
	providerServer *httptest.Server
	proxy          *OAuthProxy
	opts           *Options
}

type PassAccessTokenTestOptions struct {
	PassAccessToken bool
	ProxyUpstream   string
}

func NewPassAccessTokenTest(opts PassAccessTokenTestOptions) *PassAccessTokenTest {
	t := &PassAccessTokenTest{}

	t.providerServer = httptest.NewServer(
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
			w.Write([]byte(payload))
		}))

	t.opts = NewOptions()
	t.opts.Upstreams = append(t.opts.Upstreams, t.providerServer.URL)
	if opts.ProxyUpstream != "" {
		t.opts.Upstreams = append(t.opts.Upstreams, opts.ProxyUpstream)
	}
	// The CookieSecret must be 32 bytes in order to create the AES
	// cipher.
	t.opts.CookieSecret = "xyzzyplughxyzzyplughxyzzyplughxp"
	t.opts.ClientID = "slgkj"
	t.opts.ClientSecret = "gfjgojl"
	t.opts.CookieSecure = false
	t.opts.PassAccessToken = opts.PassAccessToken
	t.opts.Validate()

	providerURL, _ := url.Parse(t.providerServer.URL)
	const emailAddress = "michael.bland@gsa.gov"

	t.opts.provider = NewTestProvider(providerURL, emailAddress)
	t.proxy = NewOAuthProxy(t.opts, func(email string) bool {
		return email == emailAddress
	})
	return t
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
	return rw.Code, rw.HeaderMap["Set-Cookie"][1]
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
	patTest := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: true,
	})
	defer patTest.Close()

	// A successful validation will redirect and set the auth cookie.
	code, cookie := patTest.getCallbackEndpoint()
	if code != 302 {
		t.Fatalf("expected 302; got %d", code)
	}
	assert.NotEqual(t, nil, cookie)

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
	patTest := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: true,
		ProxyUpstream:   "static://200/static-proxy",
	})

	defer patTest.Close()

	// A successful validation will redirect and set the auth cookie.
	code, cookie := patTest.getCallbackEndpoint()
	if code != 302 {
		t.Fatalf("expected 302; got %d", code)
	}
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request againts the upstream proxy; And validate
	// the returned status code through the static proxy.
	code, payload := patTest.getEndpointWithCookie(cookie, "/static-proxy")
	if code != 200 {
		t.Fatalf("expected 200; got %d", code)
	}
	assert.Equal(t, "Authenticated", payload)
}

func TestDoNotForwardAccessTokenUpstream(t *testing.T) {
	patTest := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: false,
	})
	defer patTest.Close()

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
	opts                 *Options
	proxy                *OAuthProxy
	signInRegexp         *regexp.Regexp
	signInProviderRegexp *regexp.Regexp
}

const signInRedirectPattern = `<input type="hidden" name="rd" value="(.*)">`
const signInSkipProvider = `>Found<`

func NewSignInPageTest(skipProvider bool) *SignInPageTest {
	var sipTest SignInPageTest

	sipTest.opts = NewOptions()
	sipTest.opts.CookieSecret = "adklsj2"
	sipTest.opts.ClientID = "lkdgj"
	sipTest.opts.ClientSecret = "sgiufgoi"
	sipTest.opts.SkipProviderButton = skipProvider
	sipTest.opts.Validate()

	sipTest.proxy = NewOAuthProxy(sipTest.opts, func(email string) bool {
		return true
	})
	sipTest.signInRegexp = regexp.MustCompile(signInRedirectPattern)
	sipTest.signInProviderRegexp = regexp.MustCompile(signInSkipProvider)

	return &sipTest
}

func (sipTest *SignInPageTest) GetEndpoint(endpoint string) (int, string) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", endpoint, strings.NewReader(""))
	sipTest.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestSignInPageIncludesTargetRedirect(t *testing.T) {
	sipTest := NewSignInPageTest(false)
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
	sipTest := NewSignInPageTest(false)
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
	sipTest := NewSignInPageTest(true)
	const endpoint = "/some/random/endpoint"

	code, body := sipTest.GetEndpoint(endpoint)
	assert.Equal(t, 302, code)

	match := sipTest.signInProviderRegexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInSkipProvider + "\nBody:\n" + body)
	}
}

func TestSignInPageSkipProviderDirect(t *testing.T) {
	sipTest := NewSignInPageTest(true)
	const endpoint = "/sign_in"

	code, body := sipTest.GetEndpoint(endpoint)
	assert.Equal(t, 302, code)

	match := sipTest.signInProviderRegexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInSkipProvider + "\nBody:\n" + body)
	}
}

type ProcessCookieTest struct {
	opts         *Options
	proxy        *OAuthProxy
	rw           *httptest.ResponseRecorder
	req          *http.Request
	provider     TestProvider
	responseCode int
	validateUser bool
}

type ProcessCookieTestOpts struct {
	providerValidateCookieResponse bool
}

type OptionsModifier func(*Options)

func NewProcessCookieTest(opts ProcessCookieTestOpts, modifiers ...OptionsModifier) *ProcessCookieTest {
	var pcTest ProcessCookieTest

	pcTest.opts = NewOptions()
	for _, modifier := range modifiers {
		modifier(pcTest.opts)
	}
	pcTest.opts.ClientID = "asdfljk"
	pcTest.opts.ClientSecret = "lkjfdsig"
	pcTest.opts.CookieSecret = "0123456789abcdefabcd"
	// First, set the CookieRefresh option so proxy.AesCipher is created,
	// needed to encrypt the access_token.
	pcTest.opts.CookieRefresh = time.Hour
	pcTest.opts.Validate()

	pcTest.proxy = NewOAuthProxy(pcTest.opts, func(email string) bool {
		return pcTest.validateUser
	})
	pcTest.proxy.provider = &TestProvider{
		ValidToken: opts.providerValidateCookieResponse,
	}

	// Now, zero-out proxy.CookieRefresh for the cases that don't involve
	// access_token validation.
	pcTest.proxy.CookieRefresh = time.Duration(0)
	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET", "/", strings.NewReader(""))
	pcTest.validateUser = true
	return &pcTest
}

func NewProcessCookieTestWithDefaults() *ProcessCookieTest {
	return NewProcessCookieTest(ProcessCookieTestOpts{
		providerValidateCookieResponse: true,
	})
}

func NewProcessCookieTestWithOptionsModifiers(modifiers ...OptionsModifier) *ProcessCookieTest {
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
	pcTest := NewProcessCookieTestWithDefaults()

	startSession := &sessions.SessionState{Email: "john.doe@example.com", AccessToken: "my_access_token", CreatedAt: time.Now()}
	pcTest.SaveSession(startSession)

	session, err := pcTest.LoadCookiedSession()
	assert.Equal(t, nil, err)
	assert.Equal(t, startSession.Email, session.Email)
	assert.Equal(t, "john.doe@example.com", session.User)
	assert.Equal(t, startSession.AccessToken, session.AccessToken)
}

func TestProcessCookieNoCookieError(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()

	session, err := pcTest.LoadCookiedSession()
	assert.Equal(t, "Cookie \"_oauth2_proxy\" not present", err.Error())
	if session != nil {
		t.Errorf("expected nil session. got %#v", session)
	}
}

func TestProcessCookieRefreshNotSet(t *testing.T) {
	pcTest := NewProcessCookieTestWithOptionsModifiers(func(opts *Options) {
		opts.CookieExpire = time.Duration(23) * time.Hour
	})
	reference := time.Now().Add(time.Duration(-2) * time.Hour)

	startSession := &sessions.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: reference}
	pcTest.SaveSession(startSession)

	session, err := pcTest.LoadCookiedSession()
	assert.Equal(t, nil, err)
	if session.Age() < time.Duration(-2)*time.Hour {
		t.Errorf("cookie too young %v", session.Age())
	}
	assert.Equal(t, startSession.Email, session.Email)
}

func TestProcessCookieFailIfCookieExpired(t *testing.T) {
	pcTest := NewProcessCookieTestWithOptionsModifiers(func(opts *Options) {
		opts.CookieExpire = time.Duration(24) * time.Hour
	})
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &sessions.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: reference}
	pcTest.SaveSession(startSession)

	session, err := pcTest.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func TestProcessCookieFailIfRefreshSetAndCookieExpired(t *testing.T) {
	pcTest := NewProcessCookieTestWithOptionsModifiers(func(opts *Options) {
		opts.CookieExpire = time.Duration(24) * time.Hour
	})
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &sessions.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: reference}
	pcTest.SaveSession(startSession)

	pcTest.proxy.CookieRefresh = time.Hour
	session, err := pcTest.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func NewUserInfoEndpointTest() *ProcessCookieTest {
	pcTest := NewProcessCookieTestWithDefaults()
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/userinfo", nil)
	return pcTest
}

func TestUserInfoEndpointAccepted(t *testing.T) {
	test := NewUserInfoEndpointTest()
	startSession := &sessions.SessionState{
		Email: "john.doe@example.com", AccessToken: "my_access_token"}
	test.SaveSession(startSession)

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusOK, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "{\"email\":\"john.doe@example.com\"}\n", string(bodyBytes))
}

func TestUserInfoEndpointUnauthorizedOnNoCookieSetError(t *testing.T) {
	test := NewUserInfoEndpointTest()

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
}

func NewAuthOnlyEndpointTest(modifiers ...OptionsModifier) *ProcessCookieTest {
	pcTest := NewProcessCookieTestWithOptionsModifiers(modifiers...)
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/auth", nil)
	return pcTest
}

func TestAuthOnlyEndpointAccepted(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: time.Now()}
	test.SaveSession(startSession)

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusAccepted, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnNoCookieSetError(t *testing.T) {
	test := NewAuthOnlyEndpointTest()

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnExpiration(t *testing.T) {
	test := NewAuthOnlyEndpointTest(func(opts *Options) {
		opts.CookieExpire = time.Duration(24) * time.Hour
	})
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: reference}
	test.SaveSession(startSession)

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnEmailValidationFailure(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: time.Now()}
	test.SaveSession(startSession)
	test.validateUser = false

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnProviderGroupValidationFailure(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := &sessions.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token", CreatedAt: time.Now()}
	test.SaveSession(startSession)
	provider := &TestProvider{
		ValidToken: true,
		GroupValidator: func(s string) bool {
			return false
		},
	}

	test.proxy.provider = provider
	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointSetXAuthRequestHeaders(t *testing.T) {
	var pcTest ProcessCookieTest

	pcTest.opts = NewOptions()
	pcTest.opts.SetXAuthRequest = true
	pcTest.opts.Validate()

	pcTest.proxy = NewOAuthProxy(pcTest.opts, func(email string) bool {
		return pcTest.validateUser
	})
	pcTest.proxy.provider = &TestProvider{
		ValidToken: true,
	}

	pcTest.validateUser = true

	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/auth", nil)

	startSession := &sessions.SessionState{
		User: "oauth_user", Email: "oauth_user@example.com", AccessToken: "oauth_token", CreatedAt: time.Now()}
	pcTest.SaveSession(startSession)

	pcTest.proxy.ServeHTTP(pcTest.rw, pcTest.req)
	assert.Equal(t, http.StatusAccepted, pcTest.rw.Code)
	assert.Equal(t, "oauth_user", pcTest.rw.HeaderMap["X-Auth-Request-User"][0])
	assert.Equal(t, "oauth_user@example.com", pcTest.rw.HeaderMap["X-Auth-Request-Email"][0])
}

func TestAuthSkippedForPreflightRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()

	opts := NewOptions()
	opts.Upstreams = append(opts.Upstreams, upstream.URL)
	opts.ClientID = "aljsal"
	opts.ClientSecret = "jglkfsdgj"
	opts.CookieSecret = "dkfjgdls"
	opts.SkipAuthPreflight = true
	opts.Validate()

	upstreamURL, _ := url.Parse(upstream.URL)
	opts.provider = NewTestProvider(upstreamURL, "")

	proxy := NewOAuthProxy(opts, func(string) bool { return false })
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
	if result == hmacauth.ResultNoSignature {
		w.Write([]byte("no signature received"))
	} else if result == hmacauth.ResultMatch {
		w.Write([]byte("signatures match"))
	} else if result == hmacauth.ResultMismatch {
		w.Write([]byte("signatures do not match:" +
			"\n  received: " + headerSig +
			"\n  computed: " + computedSig))
	} else {
		panic("Unknown result value: " + result.String())
	}
}

type SignatureTest struct {
	opts          *Options
	upstream      *httptest.Server
	upstreamHost  string
	provider      *httptest.Server
	header        http.Header
	rw            *httptest.ResponseRecorder
	authenticator *SignatureAuthenticator
}

func NewSignatureTest() *SignatureTest {
	opts := NewOptions()
	opts.CookieSecret = "cookie secret"
	opts.ClientID = "client ID"
	opts.ClientSecret = "client secret"
	opts.EmailDomains = []string{"acm.org"}

	authenticator := &SignatureAuthenticator{}
	upstream := httptest.NewServer(
		http.HandlerFunc(authenticator.Authenticate))
	upstreamURL, _ := url.Parse(upstream.URL)
	opts.Upstreams = append(opts.Upstreams, upstream.URL)

	providerHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token": "my_auth_token"}`))
	}
	provider := httptest.NewServer(http.HandlerFunc(providerHandler))
	providerURL, _ := url.Parse(provider.URL)
	opts.provider = NewTestProvider(providerURL, "mbland@acm.org")

	return &SignatureTest{
		opts,
		upstream,
		upstreamURL.Host,
		provider,
		make(http.Header),
		httptest.NewRecorder(),
		authenticator,
	}
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

func (st *SignatureTest) MakeRequestWithExpectedKey(method, body, key string) {
	err := st.opts.Validate()
	if err != nil {
		panic(err)
	}
	proxy := NewOAuthProxy(st.opts, func(email string) bool { return true })

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
		panic(err)
	}
	for _, c := range st.rw.Result().Cookies() {
		req.AddCookie(c)
	}
	// This is used by the upstream to validate the signature.
	st.authenticator.auth = hmacauth.NewHmacAuth(
		crypto.SHA1, []byte(key), SignatureHeader, SignatureHeaders)
	proxy.ServeHTTP(st.rw, req)
}

func TestNoRequestSignature(t *testing.T) {
	st := NewSignatureTest()
	defer st.Close()
	st.MakeRequestWithExpectedKey("GET", "", "")
	assert.Equal(t, 200, st.rw.Code)
	assert.Equal(t, st.rw.Body.String(), "no signature received")
}

func TestRequestSignatureGetRequest(t *testing.T) {
	st := NewSignatureTest()
	defer st.Close()
	st.opts.SignatureKey = "sha1:7d9e1aa87a5954e6f9fc59266b3af9d7c35fda2d"
	st.MakeRequestWithExpectedKey("GET", "", "7d9e1aa87a5954e6f9fc59266b3af9d7c35fda2d")
	assert.Equal(t, 200, st.rw.Code)
	assert.Equal(t, st.rw.Body.String(), "signatures match")
}

func TestRequestSignaturePostRequest(t *testing.T) {
	st := NewSignatureTest()
	defer st.Close()
	st.opts.SignatureKey = "sha1:d90df39e2d19282840252612dd7c81421a372f61"
	payload := `{ "hello": "world!" }`
	st.MakeRequestWithExpectedKey("POST", payload, "d90df39e2d19282840252612dd7c81421a372f61")
	assert.Equal(t, 200, st.rw.Code)
	assert.Equal(t, st.rw.Body.String(), "signatures match")
}

func TestGetRedirect(t *testing.T) {
	options := NewOptions()
	_ = options.Validate()
	require.NotEmpty(t, options.ProxyPrefix)
	proxy := NewOAuthProxy(options, func(s string) bool { return false })

	tests := []struct {
		name             string
		url              string
		expectedRedirect string
	}{
		{
			name:             "request outside of ProxyPrefix redirects to original URL",
			url:              "/foo/bar",
			expectedRedirect: "/foo/bar",
		},
		{
			name:             "request under ProxyPrefix redirects to root",
			url:              proxy.ProxyPrefix + "/foo/bar",
			expectedRedirect: "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			redirect, err := proxy.GetRedirect(req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedRedirect, redirect)
		})
	}
}

type ajaxRequestTest struct {
	opts  *Options
	proxy *OAuthProxy
}

func newAjaxRequestTest() *ajaxRequestTest {
	test := &ajaxRequestTest{}
	test.opts = NewOptions()
	test.opts.CookieSecret = "sdflsw"
	test.opts.ClientID = "gkljfdl"
	test.opts.ClientSecret = "sdflkjs"
	test.opts.Validate()
	test.proxy = NewOAuthProxy(test.opts, func(email string) bool {
		return true
	})
	return test
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
	test := newAjaxRequestTest()
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

func TestAjaxForbiddendRequest(t *testing.T) {
	test := newAjaxRequestTest()
	endpoint := "/test"
	header := make(http.Header)
	code, rh, err := test.getEndpoint(endpoint, header)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, code)
	mime := rh.Get("Content-Type")
	assert.NotEqual(t, applicationJSON, mime)
}

func TestClearSplitCookie(t *testing.T) {
	opts := NewOptions()
	opts.CookieName = "oauth2"
	opts.CookieDomain = "abc"
	store, err := cookie.NewCookieSessionStore(&opts.SessionOptions, &opts.CookieOptions)
	assert.Equal(t, err, nil)
	p := OAuthProxy{CookieName: opts.CookieName, CookieDomain: opts.CookieDomain, sessionStore: store}
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

	p.ClearSessionCookie(rw, req)
	header := rw.Header()

	assert.Equal(t, 2, len(header["Set-Cookie"]), "should have 3 set-cookie header entries")
}

func TestClearSingleCookie(t *testing.T) {
	opts := NewOptions()
	opts.CookieName = "oauth2"
	opts.CookieDomain = "abc"
	store, err := cookie.NewCookieSessionStore(&opts.SessionOptions, &opts.CookieOptions)
	assert.Equal(t, err, nil)
	p := OAuthProxy{CookieName: opts.CookieName, CookieDomain: opts.CookieDomain, sessionStore: store}
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

	p.ClearSessionCookie(rw, req)
	header := rw.Header()

	assert.Equal(t, 1, len(header["Set-Cookie"]), "should have 1 set-cookie header entries")
}

type NoOpKeySet struct {
}

func (NoOpKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	splitStrings := strings.Split(jwt, ".")
	payloadString := splitStrings[1]
	jsonString, err := base64.RawURLEncoding.DecodeString(payloadString)
	return []byte(jsonString), err
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

	test := NewAuthOnlyEndpointTest(func(opts *Options) {
		opts.PassAuthorization = true
		opts.SetAuthorization = true
		opts.SetXAuthRequest = true
		opts.SkipJwtBearerTokens = true
		opts.jwtBearerVerifiers = append(opts.jwtBearerVerifiers, verifier)
	})
	tp, _ := test.proxy.provider.(*TestProvider)
	tp.GroupValidator = func(s string) bool {
		return true
	}

	authHeader := fmt.Sprintf("Bearer %s", goodJwt)
	test.req.Header = map[string][]string{
		"Authorization": {authHeader},
	}

	// Bearer
	session, _ := test.proxy.GetJwtSession(test.req)
	assert.Equal(t, session.User, "john@example.com")
	assert.Equal(t, session.Email, "john@example.com")
	assert.Equal(t, session.ExpiresOn, time.Unix(1912151821, 0))
	assert.Equal(t, session.IDToken, goodJwt)

	test.proxy.ServeHTTP(test.rw, test.req)
	if test.rw.Code >= 400 {
		t.Fatalf("expected 3xx got %d", test.rw.Code)
	}

	// Check PassAuthorization, should overwrite Basic header
	assert.Equal(t, test.req.Header.Get("Authorization"), authHeader)
	assert.Equal(t, test.req.Header.Get("X-Forwarded-User"), "john@example.com")
	assert.Equal(t, test.req.Header.Get("X-Forwarded-Email"), "john@example.com")

	// SetAuthorization and SetXAuthRequest
	assert.Equal(t, test.rw.Header().Get("Authorization"), authHeader)
	assert.Equal(t, test.rw.Header().Get("X-Auth-Request-User"), "john@example.com")
	assert.Equal(t, test.rw.Header().Get("X-Auth-Request-Email"), "john@example.com")
}

func TestJwtUnauthorizedOnGroupValidationFailure(t *testing.T) {
	goodJwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly90ZXN0Lm15YXBwLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsImVtY" +
		"WlsIjoiam9obkBleGFtcGxlLmNvbSIsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNTUzNjkxMj" +
		"E1LCJleHAiOjE5MTIxNTE4MjF9." +
		"rLVyzOnEldUq_pNkfa-WiV8TVJYWyZCaM2Am_uo8FGg11zD7l-qmz3x1seTvqpH6Y0Ty00fmv6dJnGnC8WMnPXQiodRTfhBSe" +
		"OKZMu0HkMD2sg52zlKkbfLTO6ic5VnbVgwjjrB8am_Ta6w7kyFUaB5C1BsIrrLMldkWEhynbb8"

	keyset := NoOpKeySet{}
	verifier := oidc.NewVerifier("https://issuer.example.com", keyset,
		&oidc.Config{ClientID: "https://test.myapp.com", SkipExpiryCheck: true})

	test := NewAuthOnlyEndpointTest(func(opts *Options) {
		opts.PassAuthorization = true
		opts.SetAuthorization = true
		opts.SetXAuthRequest = true
		opts.SkipJwtBearerTokens = true
		opts.jwtBearerVerifiers = append(opts.jwtBearerVerifiers, verifier)
	})
	tp, _ := test.proxy.provider.(*TestProvider)
	// Verify ValidateGroup fails JWT authorization
	tp.GroupValidator = func(s string) bool {
		return false
	}

	authHeader := fmt.Sprintf("Bearer %s", goodJwt)
	test.req.Header = map[string][]string{
		"Authorization": {authHeader},
	}
	test.proxy.ServeHTTP(test.rw, test.req)
	if test.rw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d", test.rw.Code)
	}
}

func TestFindJwtBearerToken(t *testing.T) {
	p := OAuthProxy{CookieName: "oauth2", CookieDomain: "abc"}
	getReq := &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}}

	validToken := "eyJfoobar.eyJfoobar.12345asdf"
	var token string

	// Bearer
	getReq.Header = map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", validToken)},
	}

	token, _ = p.findBearerToken(getReq)
	assert.Equal(t, validToken, token)

	// Basic - no password
	getReq.SetBasicAuth(token, "")
	token, _ = p.findBearerToken(getReq)
	assert.Equal(t, validToken, token)

	// Basic - sentinel password
	getReq.SetBasicAuth(token, "x-oauth-basic")
	token, _ = p.findBearerToken(getReq)
	assert.Equal(t, validToken, token)

	// Basic - any username, password matching jwt pattern
	getReq.SetBasicAuth("any-username-you-could-wish-for", token)
	token, _ = p.findBearerToken(getReq)
	assert.Equal(t, validToken, token)

	failures := []string{
		// Too many parts
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.dGVzdA.dGVzdA.dGVzdA.dGVzdA.dGVzdA",
		// Not enough parts
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.dGVzdA.dGVzdA.dGVzdA",
		// Invalid encrypted key
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.//////.dGVzdA.dGVzdA.dGVzdA",
		// Invalid IV
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.dGVzdA.//////.dGVzdA.dGVzdA",
		// Invalid ciphertext
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.dGVzdA.dGVzdA.//////.dGVzdA",
		// Invalid tag
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.dGVzdA.dGVzdA.dGVzdA.//////",
		// Invalid header
		"W10.dGVzdA.dGVzdA.dGVzdA.dGVzdA",
		// Invalid header
		"######.dGVzdA.dGVzdA.dGVzdA.dGVzdA",
		// Missing alc/enc params
		"e30.dGVzdA.dGVzdA.dGVzdA.dGVzdA",
	}

	for _, failure := range failures {
		getReq.Header = map[string][]string{
			"Authorization": {fmt.Sprintf("Bearer %s", failure)},
		}
		_, err := p.findBearerToken(getReq)
		assert.Error(t, err)
	}

	fmt.Printf("%s", token)
}
