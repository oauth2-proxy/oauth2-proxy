package main

import (
	"crypto"
	"encoding/base64"
	"github.com/18F/hmacauth"
	"github.com/bitly/oauth2_proxy/providers"
	"github.com/bmizerany/assert"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

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

	proxyHandler := NewReverseProxy(proxyURL)
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
	proxyHandler := NewReverseProxy(b)
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

type TestProvider struct {
	*providers.ProviderData
	EmailAddress string
	ValidToken   bool
}

func NewTestProvider(provider_url *url.URL, email_address string) *TestProvider {
	return &TestProvider{
		ProviderData: &providers.ProviderData{
			ProviderName: "Test Provider",
			LoginURL: &url.URL{
				Scheme: "http",
				Host:   provider_url.Host,
				Path:   "/oauth/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   provider_url.Host,
				Path:   "/oauth/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   provider_url.Host,
				Path:   "/api/v1/profile",
			},
			Scope: "profile.email",
		},
		EmailAddress: email_address,
	}
}

func (tp *TestProvider) GetEmailAddress(session *providers.SessionState) (string, error) {
	return tp.EmailAddress, nil
}

func (tp *TestProvider) ValidateSessionState(session *providers.SessionState) bool {
	return tp.ValidToken
}

func TestBasicAuthPassword(t *testing.T) {
	provider_server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%#v", r)
		url := r.URL
		payload := ""
		switch url.Path {
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
	opts.Upstreams = append(opts.Upstreams, provider_server.URL)
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

	provider_url, _ := url.Parse(provider_server.URL)
	const email_address = "michael.bland@gsa.gov"
	const user_name = "michael.bland"

	opts.provider = NewTestProvider(provider_url, email_address)
	proxy := NewOAuthProxy(opts, func(email string) bool {
		return email == email_address
	})

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/oauth2/callback?code=callback_code",
		strings.NewReader(""))
	proxy.ServeHTTP(rw, req)
	cookie := rw.HeaderMap["Set-Cookie"][0]

	cookieName := proxy.CookieName
	var value string
	key_prefix := cookieName + "="

	for _, field := range strings.Split(cookie, "; ") {
		value = strings.TrimPrefix(field, key_prefix)
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

	rw = httptest.NewRecorder()
	proxy.ServeHTTP(rw, req)
	expectedHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(user_name+":"+opts.BasicAuthPassword))
	assert.Equal(t, expectedHeader, rw.Body.String())
	provider_server.Close()
}

type PassAccessTokenTest struct {
	provider_server *httptest.Server
	proxy           *OAuthProxy
	opts            *Options
}

type PassAccessTokenTestOptions struct {
	PassAccessToken bool
}

func NewPassAccessTokenTest(opts PassAccessTokenTestOptions) *PassAccessTokenTest {
	t := &PassAccessTokenTest{}

	t.provider_server = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%#v", r)
			url := r.URL
			payload := ""
			switch url.Path {
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
	t.opts.Upstreams = append(t.opts.Upstreams, t.provider_server.URL)
	// The CookieSecret must be 32 bytes in order to create the AES
	// cipher.
	t.opts.CookieSecret = "xyzzyplughxyzzyplughxyzzyplughxp"
	t.opts.ClientID = "bazquux"
	t.opts.ClientSecret = "foobar"
	t.opts.CookieSecure = false
	t.opts.PassAccessToken = opts.PassAccessToken
	t.opts.Validate()

	provider_url, _ := url.Parse(t.provider_server.URL)
	const email_address = "michael.bland@gsa.gov"

	t.opts.provider = NewTestProvider(provider_url, email_address)
	t.proxy = NewOAuthProxy(t.opts, func(email string) bool {
		return email == email_address
	})
	return t
}

func (pat_test *PassAccessTokenTest) Close() {
	pat_test.provider_server.Close()
}

func (pat_test *PassAccessTokenTest) getCallbackEndpoint() (http_code int,
	cookie string) {
	rw := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/oauth2/callback?code=callback_code",
		strings.NewReader(""))
	if err != nil {
		return 0, ""
	}
	pat_test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.HeaderMap["Set-Cookie"][0]
}

func (pat_test *PassAccessTokenTest) getRootEndpoint(cookie string) (http_code int, access_token string) {
	cookieName := pat_test.proxy.CookieName
	var value string
	key_prefix := cookieName + "="

	for _, field := range strings.Split(cookie, "; ") {
		value = strings.TrimPrefix(field, key_prefix)
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
	pat_test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestForwardAccessTokenUpstream(t *testing.T) {
	pat_test := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: true,
	})
	defer pat_test.Close()

	// A successful validation will redirect and set the auth cookie.
	code, cookie := pat_test.getCallbackEndpoint()
	assert.Equal(t, 302, code)
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request; the access_token from the cookie is
	// forwarded as the "X-Forwarded-Access-Token" header. The token is
	// read by the test provider server and written in the response body.
	code, payload := pat_test.getRootEndpoint(cookie)
	assert.Equal(t, 200, code)
	assert.Equal(t, "my_auth_token", payload)
}

func TestDoNotForwardAccessTokenUpstream(t *testing.T) {
	pat_test := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: false,
	})
	defer pat_test.Close()

	// A successful validation will redirect and set the auth cookie.
	code, cookie := pat_test.getCallbackEndpoint()
	assert.Equal(t, 302, code)
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request, but the access token header should
	// not be present.
	code, payload := pat_test.getRootEndpoint(cookie)
	assert.Equal(t, 200, code)
	assert.Equal(t, "No access token found.", payload)
}

type SignInPageTest struct {
	opts           *Options
	proxy          *OAuthProxy
	sign_in_regexp *regexp.Regexp
}

const signInRedirectPattern = `<input type="hidden" name="rd" value="(.*)">`

func NewSignInPageTest() *SignInPageTest {
	var sip_test SignInPageTest

	sip_test.opts = NewOptions()
	sip_test.opts.CookieSecret = "foobar"
	sip_test.opts.ClientID = "bazquux"
	sip_test.opts.ClientSecret = "xyzzyplugh"
	sip_test.opts.Validate()

	sip_test.proxy = NewOAuthProxy(sip_test.opts, func(email string) bool {
		return true
	})
	sip_test.sign_in_regexp = regexp.MustCompile(signInRedirectPattern)

	return &sip_test
}

func (sip_test *SignInPageTest) GetEndpoint(endpoint string) (int, string) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", endpoint, strings.NewReader(""))
	sip_test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestSignInPageIncludesTargetRedirect(t *testing.T) {
	sip_test := NewSignInPageTest()
	const endpoint = "/some/random/endpoint"

	code, body := sip_test.GetEndpoint(endpoint)
	assert.Equal(t, 403, code)

	match := sip_test.sign_in_regexp.FindStringSubmatch(body)
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
	sip_test := NewSignInPageTest()
	code, body := sip_test.GetEndpoint("/oauth2/sign_in")
	assert.Equal(t, 200, code)

	match := sip_test.sign_in_regexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInRedirectPattern + "\nBody:\n" + body)
	}
	if match[1] != "/" {
		t.Fatal(`expected redirect to "/", but was "` + match[1] + `"`)
	}
}

type ProcessCookieTest struct {
	opts          *Options
	proxy         *OAuthProxy
	rw            *httptest.ResponseRecorder
	req           *http.Request
	provider      TestProvider
	response_code int
	validate_user bool
}

type ProcessCookieTestOpts struct {
	provider_validate_cookie_response bool
}

func NewProcessCookieTest(opts ProcessCookieTestOpts) *ProcessCookieTest {
	var pc_test ProcessCookieTest

	pc_test.opts = NewOptions()
	pc_test.opts.ClientID = "bazquux"
	pc_test.opts.ClientSecret = "xyzzyplugh"
	pc_test.opts.CookieSecret = "0123456789abcdefabcd"
	// First, set the CookieRefresh option so proxy.AesCipher is created,
	// needed to encrypt the access_token.
	pc_test.opts.CookieRefresh = time.Hour
	pc_test.opts.Validate()

	pc_test.proxy = NewOAuthProxy(pc_test.opts, func(email string) bool {
		return pc_test.validate_user
	})
	pc_test.proxy.provider = &TestProvider{
		ValidToken: opts.provider_validate_cookie_response,
	}

	// Now, zero-out proxy.CookieRefresh for the cases that don't involve
	// access_token validation.
	pc_test.proxy.CookieRefresh = time.Duration(0)
	pc_test.rw = httptest.NewRecorder()
	pc_test.req, _ = http.NewRequest("GET", "/", strings.NewReader(""))
	pc_test.validate_user = true
	return &pc_test
}

func NewProcessCookieTestWithDefaults() *ProcessCookieTest {
	return NewProcessCookieTest(ProcessCookieTestOpts{
		provider_validate_cookie_response: true,
	})
}

func (p *ProcessCookieTest) MakeCookie(value string, ref time.Time) *http.Cookie {
	return p.proxy.MakeCookie(p.req, value, p.opts.CookieExpire, ref)
}

func (p *ProcessCookieTest) SaveSession(s *providers.SessionState, ref time.Time) error {
	value, err := p.proxy.provider.CookieForSession(s, p.proxy.CookieCipher)
	if err != nil {
		return err
	}
	p.req.AddCookie(p.proxy.MakeCookie(p.req, value, p.proxy.CookieExpire, ref))
	return nil
}

func (p *ProcessCookieTest) LoadCookiedSession() (*providers.SessionState, time.Duration, error) {
	return p.proxy.LoadCookiedSession(p.req)
}

func TestLoadCookiedSession(t *testing.T) {
	pc_test := NewProcessCookieTestWithDefaults()

	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pc_test.SaveSession(startSession, time.Now())

	session, _, err := pc_test.LoadCookiedSession()
	assert.Equal(t, nil, err)
	assert.Equal(t, startSession.Email, session.Email)
	assert.Equal(t, "michael.bland", session.User)
	assert.Equal(t, startSession.AccessToken, session.AccessToken)
}

func TestProcessCookieNoCookieError(t *testing.T) {
	pc_test := NewProcessCookieTestWithDefaults()

	session, _, err := pc_test.LoadCookiedSession()
	assert.Equal(t, "Cookie \"_oauth2_proxy\" not present", err.Error())
	if session != nil {
		t.Errorf("expected nil session. got %#v", session)
	}
}

func TestProcessCookieRefreshNotSet(t *testing.T) {
	pc_test := NewProcessCookieTestWithDefaults()
	pc_test.proxy.CookieExpire = time.Duration(23) * time.Hour
	reference := time.Now().Add(time.Duration(-2) * time.Hour)

	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pc_test.SaveSession(startSession, reference)

	session, age, err := pc_test.LoadCookiedSession()
	assert.Equal(t, nil, err)
	if age < time.Duration(-2)*time.Hour {
		t.Errorf("cookie too young %v", age)
	}
	assert.Equal(t, startSession.Email, session.Email)
}

func TestProcessCookieFailIfCookieExpired(t *testing.T) {
	pc_test := NewProcessCookieTestWithDefaults()
	pc_test.proxy.CookieExpire = time.Duration(24) * time.Hour
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pc_test.SaveSession(startSession, reference)

	session, _, err := pc_test.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func TestProcessCookieFailIfRefreshSetAndCookieExpired(t *testing.T) {
	pc_test := NewProcessCookieTestWithDefaults()
	pc_test.proxy.CookieExpire = time.Duration(24) * time.Hour
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := &providers.SessionState{Email: "michael.bland@gsa.gov", AccessToken: "my_access_token"}
	pc_test.SaveSession(startSession, reference)

	pc_test.proxy.CookieRefresh = time.Hour
	session, _, err := pc_test.LoadCookiedSession()
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expected nil session %#v", session)
	}
}

func NewAuthOnlyEndpointTest() *ProcessCookieTest {
	pc_test := NewProcessCookieTestWithDefaults()
	pc_test.req, _ = http.NewRequest("GET",
		pc_test.opts.ProxyPrefix+"/auth", nil)
	return pc_test
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
	test.validate_user = false

	test.proxy.ServeHTTP(test.rw, test.req)
	assert.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	assert.Equal(t, "unauthorized request\n", string(bodyBytes))
}

type SignatureAuthenticator struct {
	auth hmacauth.HmacAuth
}

func (v *SignatureAuthenticator) Authenticate(
	w http.ResponseWriter, r *http.Request) {
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
	upstream_host string
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
	upstream_url, _ := url.Parse(upstream.URL)
	opts.Upstreams = append(opts.Upstreams, upstream.URL)

	providerHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token": "my_auth_token"}`))
	}
	provider := httptest.NewServer(http.HandlerFunc(providerHandler))
	provider_url, _ := url.Parse(provider.URL)
	opts.provider = NewTestProvider(provider_url, "mbland@acm.org")

	return &SignatureTest{
		opts,
		upstream,
		upstream_url.Host,
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
	req, err := http.NewRequest(method, "/foo/bar", bodyBuf)
	if err != nil {
		panic(err)
	}
	req.Header = st.header

	state := &providers.SessionState{
		Email: "mbland@acm.org", AccessToken: "my_access_token"}
	value, err := proxy.provider.CookieForSession(state, proxy.CookieCipher)
	if err != nil {
		panic(err)
	}
	cookie := proxy.MakeCookie(req, value, proxy.CookieExpire, time.Now())
	req.AddCookie(cookie)
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
