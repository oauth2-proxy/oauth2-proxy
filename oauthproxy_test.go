package main

import (
	"crypto"
	"encoding/base64"
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

	"github.com/mbland/hmacauth"
	"github.com/pusher/oauth2_proxy/logger"
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

	proxyHandler := NewReverseProxy(proxyURL, time.Second)
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
	proxyHandler := NewReverseProxy(b, time.Second)
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
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = "xyzzyplugh"
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
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = "xyzzyplugh"
	// Should match domains that are exactly foo.bar and any subdomain of bar.foo
	opts.WhitelistDomains = []string{"foo.bar", ".bar.foo"}
	opts.Validate()

	proxy := NewOAuthProxy(opts, func(string) bool { return true })

	noRD := proxy.IsValidRedirect("")
	assert.Equal(t, false, noRD)

	singleSlash := proxy.IsValidRedirect("/redirect")
	assert.Equal(t, true, singleSlash)

	doubleSlash := proxy.IsValidRedirect("//redirect")
	assert.Equal(t, false, doubleSlash)

	validHTTP := proxy.IsValidRedirect("http://foo.bar/redirect")
	assert.Equal(t, true, validHTTP)

	validHTTPS := proxy.IsValidRedirect("https://foo.bar/redirect")
	assert.Equal(t, true, validHTTPS)

	invalidHTTPSubdomain := proxy.IsValidRedirect("http://baz.foo.bar/redirect")
	assert.Equal(t, false, invalidHTTPSubdomain)

	invalidHTTPSSubdomain := proxy.IsValidRedirect("https://baz.foo.bar/redirect")
	assert.Equal(t, false, invalidHTTPSSubdomain)

	validHTTPSubdomain := proxy.IsValidRedirect("http://baz.bar.foo/redirect")
	assert.Equal(t, true, validHTTPSubdomain)

	validHTTPSSubdomain := proxy.IsValidRedirect("https://baz.bar.foo/redirect")
	assert.Equal(t, true, validHTTPSSubdomain)

	invalidHTTP1 := proxy.IsValidRedirect("http://foo.bar.evil.corp/redirect")
	assert.Equal(t, false, invalidHTTP1)

	invalidHTTPS1 := proxy.IsValidRedirect("https://foo.bar.evil.corp/redirect")
	assert.Equal(t, false, invalidHTTPS1)

	invalidHTTP2 := proxy.IsValidRedirect("http://evil.corp/redirect?rd=foo.bar")
	assert.Equal(t, false, invalidHTTP2)

	invalidHTTPS2 := proxy.IsValidRedirect("https://evil.corp/redirect?rd=foo.bar")
	assert.Equal(t, false, invalidHTTPS2)
}

type TestProvider struct {
	*providers.ProviderData
	EmailAddress string
	ValidToken   bool
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
	}
}

func (tp *TestProvider) GetEmailAddress(session *providers.SessionState) (string, error) {
	return tp.EmailAddress, nil
}

func (tp *TestProvider) ValidateSessionState(session *providers.SessionState) bool {
	return tp.ValidToken
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
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
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
}

func NewPassAccessTokenTest(opts PassAccessTokenTestOptions) *PassAccessTokenTest {
	t := &PassAccessTokenTest{}

	t.providerServer = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Printf("%#v", r)
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
	// The CookieSecret must be 32 bytes in order to create the AES
	// cipher.
	t.opts.CookieSecret = "xyzzyplughxyzzyplughxyzzyplughxp"
	t.opts.ClientID = "bazquux"
	t.opts.ClientSecret = "foobar"
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

func (patTest *PassAccessTokenTest) getRootEndpoint(cookie string) (httpCode int, accessToken string) {
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

	req, err := http.NewRequest("GET", "/", strings.NewReader(""))
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
	code, payload := patTest.getRootEndpoint(cookie)
	if code != 200 {
		t.Fatalf("expected 200; got %d", code)
	}
	assert.Equal(t, "my_auth_token", payload)
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
	code, payload := patTest.getRootEndpoint(cookie)
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
	sipTest.opts.CookieSecret = "foobar"
	sipTest.opts.ClientID = "bazquux"
	sipTest.opts.ClientSecret = "xyzzyplugh"
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

func NewProcessCookieTest(opts ProcessCookieTestOpts) *ProcessCookieTest {
	var pcTest ProcessCookieTest

	pcTest.opts = NewOptions()
	pcTest.opts.ClientID = "bazquux"
	pcTest.opts.ClientSecret = "xyzzyplugh"
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

func (p *ProcessCookieTest) MakeCookie(value string, ref time.Time) []*http.Cookie {
	return p.proxy.MakeSessionCookie(p.req, value, p.opts.CookieExpire, ref)
}

func (p *ProcessCookieTest) SaveSession(s *providers.SessionState, ref time.Time) error {
	value, err := p.proxy.provider.CookieForSession(s, p.proxy.CookieCipher)
	if err != nil {
		return err
	}
	for _, c := range p.proxy.MakeSessionCookie(p.req, value, p.proxy.CookieExpire, ref) {
		p.req.AddCookie(c)
	}
	return nil
}

func (p *ProcessCookieTest) LoadCookiedSession() (*providers.SessionState, time.Duration, error) {
	return p.proxy.LoadCookiedSession(p.req)
}

func TestLoadCookiedSession(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()

	startSession := &providers.SessionState{Email: "john.doe@example.com", AccessToken: "my_access_token"}
	pcTest.SaveSession(startSession, time.Now())

	session, _, err := pcTest.LoadCookiedSession()
	assert.Equal(t, nil, err)
	assert.Equal(t, startSession.Email, session.Email)
	assert.Equal(t, "john.doe@example.com", session.User)
	assert.Equal(t, startSession.AccessToken, session.AccessToken)
}

func TestProcessCookieNoCookieError(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()

	session, _, err := pcTest.LoadCookiedSession()
	assert.Equal(t, "Cookie \"_oauth2_proxy\" not present", err.Error())
	if session != nil {
		t.Errorf("expected nil session. got %#v", session)
	}
}

func TestProcessCookieRefreshNotSet(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()
	pcTest.proxy.CookieExpire = time.Duration(23) * time.Hour
	reference := time.Now().Add(time.Duration(-2) * time.Hour)

	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pcTest.SaveSession(startSession, reference)

	session, age, err := pcTest.LoadCookiedSession()
	assert.Equal(t, nil, err)
	if age < time.Duration(-2)*time.Hour {
		t.Errorf("cookie too young %v", age)
	}
	assert.Equal(t, startSession.Email, session.Email)
}

func TestProcessCookieFailIfCookieExpired(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()
	pcTest.proxy.CookieExpire = time.Duration(24) * time.Hour
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pcTest.SaveSession(startSession, reference)

	session, _, err := pcTest.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func TestProcessCookieFailIfRefreshSetAndCookieExpired(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()
	pcTest.proxy.CookieExpire = time.Duration(24) * time.Hour
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pcTest.SaveSession(startSession, reference)

	pcTest.proxy.CookieRefresh = time.Hour
	session, _, err := pcTest.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func NewAuthOnlyEndpointTest() *ProcessCookieTest {
	pcTest := NewProcessCookieTestWithDefaults()
	pcTest.req, _ = http.NewRequest("GET",
		pcTest.opts.ProxyPrefix+"/auth", nil)
	return pcTest
}

func TestAuthOnlyEndpointAccepted(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := &providers.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	test.SaveSession(startSession, time.Now())

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
	test := NewAuthOnlyEndpointTest()
	test.proxy.CookieExpire = time.Duration(24) * time.Hour
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &providers.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	test.SaveSession(startSession, reference)

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnEmailValidationFailure(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := &providers.SessionState{
		Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	test.SaveSession(startSession, time.Now())
	test.validateUser = false

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

	startSession := &providers.SessionState{
		User: "oauth_user", Email: "oauth_user@example.com", AccessToken: "oauth_token"}
	pcTest.SaveSession(startSession, time.Now())

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
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = "xyzzyplugh"
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

	state := &providers.SessionState{
		Email: "mbland@acm.org", AccessToken: "my_access_token"}
	value, err := proxy.provider.CookieForSession(state, proxy.CookieCipher)
	if err != nil {
		panic(err)
	}
	for _, c := range proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now()) {
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
	st.opts.SignatureKey = "sha1:foobar"
	st.MakeRequestWithExpectedKey("GET", "", "foobar")
	assert.Equal(t, 200, st.rw.Code)
	assert.Equal(t, st.rw.Body.String(), "signatures match")
}

func TestRequestSignaturePostRequest(t *testing.T) {
	st := NewSignatureTest()
	defer st.Close()
	st.opts.SignatureKey = "sha1:foobar"
	payload := `{ "hello": "world!" }`
	st.MakeRequestWithExpectedKey("POST", payload, "foobar")
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
	test.opts.CookieSecret = "foobar"
	test.opts.ClientID = "bazquux"
	test.opts.ClientSecret = "xyzzyplugh"
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
	p := OAuthProxy{CookieName: "oauth2", CookieDomain: "abc"}
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
	p := OAuthProxy{CookieName: "oauth2", CookieDomain: "abc"}
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
